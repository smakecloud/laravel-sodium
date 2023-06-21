<?php

namespace Smakecloud\Sodium\Encryption;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use RuntimeException;

class Encrypter implements EncrypterContract, StringEncrypter
{
    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher;

    /**
     * The supported cipher algorithms and their properties.
     *
     * @var array<string, array<string, int<1, max>>>
     */
    private static $supportedCiphers = [
        'aes-256-gcm' => [
            'keySize' => SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES,
            'nonceSize' => SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES,
        ],
        'xcha-cha20-poly1305' => [
            'keySize' => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            'nonceSize' => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
        ],
    ];

    /**
     * Create a new encrypter instance.
     *
     * @param  string  $key
     * @param  string  $cipher
     * @return void
     *
     * @throws \RuntimeException
     */
    public function __construct($key, $cipher = 'xcha-cha20-poly1305')
    {
        if (! static::supported($key, $cipher)) {
            $ciphers = implode(', ', array_keys(self::$supportedCiphers));

            throw new RuntimeException("Unsupported cipher or incorrect key length. Supported ciphers are: {$ciphers}. Got {$cipher} with key length ".mb_strlen($key, '8bit').'.');
        }

        $this->cipher = $cipher;
        $this->key = $key;
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param  string  $key
     * @param  string  $cipher
     * @return bool
     */
    public static function supported($key, $cipher)
    {
        if (! isset(self::$supportedCiphers[strtolower($cipher)])) {
            return false;
        }

        return mb_strlen($key, '8bit') === self::$supportedCiphers[strtolower($cipher)]['keySize'];
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @param  string  $cipher
     * @return string
     */
    public static function generateKey($cipher)
    {
        return match (strtolower($cipher)) {
            'aes-256-gcm' => sodium_crypto_aead_aes256gcm_keygen(),
            'xcha-cha20-poly1305' => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
            default => throw new RuntimeException('Unsupported cipher provided.'),
        };
    }

    /**
     * Create a nonce for the given cipher.
     *
     * @param  string  $cipher
     * @return string
     */
    public static function generateNonce($cipher)
    {
        return random_bytes(self::$supportedCiphers[strtolower($cipher)]['nonceSize']);
    }

    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     */
    public function encrypt($value, $serialize = true)
    {
        $value = $serialize ? serialize($value) : $value;

        if (! is_string($value)) {
            throw new EncryptException('The value to encrypt must be string.');
        }

        try {
            $nonce = self::generateNonce($this->cipher);

            $encrypted = self::encryptUsign(
                $value,
                $this->key,
                $nonce,
                $this->cipher
            );
        } catch (\Throwable $e) {
            throw new EncryptException('Could not encrypt the data.', 0, $e);
        }

        $json = json_encode([
            'nonce' => base64_encode($nonce),
            'encrypted' => base64_encode($encrypted),
        ], JSON_UNESCAPED_SLASHES);

        if (! is_string($json)) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    /**
     * Decrypt the given value.
     *
     * @param  string  $payload
     * @param  bool  $unserialize
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    public function decrypt($payload, $unserialize = true)
    {
        try {
            $payload = $this->getJsonPayload($payload);

            $decrypted = self::decryptUsign(
                base64_decode($payload['encrypted']),
                $this->key,
                base64_decode($payload['nonce']),
                $this->cipher
            );
        } catch (\Throwable $e) {
            throw new DecryptException('Could not decrypt the data.', 0, $e);
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     */
    public function encryptString($value)
    {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param  string  $payload
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    public function decryptString($payload)
    {
        $decrypted = $this->decrypt($payload, false);

        if (! is_string($decrypted)) {
            throw new DecryptException('The payload is invalid.');
        }

        return $decrypted;
    }

    /**
     * Get the JSON array from the given payload.
     *
     * @return array<string, string>
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    protected function getJsonPayload(string $payload): array
    {
        $payload = json_decode(base64_decode($payload), true);

        if (! is_array($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        if (! $payload || $this->invalidPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        return $payload;
    }

    /**
     * Check if the payload is invalid.
     *
     * @param  array<mixed>  $data
     * @return bool
     */
    protected function invalidPayload($data)
    {
        return ! isset($data['nonce']) || ! isset($data['encrypted']) ||
            ! is_string($data['nonce']) || ! is_string($data['encrypted']);
    }

    /**
     * Get the encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Encrypt the given value using sodium aes256gcm or xcha-cha20-poly1305.
     *
     * @param  string  $data
     * @param  string  $key
     * @param  string  $nonce
     * @param  string  $cipher
     * @param  string  $tag
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     */
    public static function encryptUsign($data, $key, $nonce, $cipher, $tag = '')
    {
        return match (strtolower($cipher)) {
            'aes-256-gcm' => sodium_crypto_aead_aes256gcm_encrypt(
                $data,
                $tag,
                $nonce,
                $key
            ),
            'xcha-cha20-poly1305' => sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $data,
                $tag,
                $nonce,
                $key
            ),
            default => throw new EncryptException('The only supported ciphers are AES-256-GCM and XChaCha20-Poly1305.'),
        };
    }

    /**
     * Decrypt the given value using sodium aes256gcm or xcha-cha20-poly1305.
     *
     * @param  string  $data
     * @param  string  $key
     * @param  string  $nonce
     * @param  string  $cipher
     * @param  string  $tag
     * @return string
     *
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     */
    public static function decryptUsign($data, $key, $nonce, $cipher, $tag = '')
    {
        $decrypted = match (strtolower($cipher)) {
            'aes-256-gcm' => sodium_crypto_aead_aes256gcm_decrypt(
                $data,
                $tag,
                $nonce,
                $key
            ),
            'xcha-cha20-poly1305' => sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $data,
                $tag,
                $nonce,
                $key
            ),
            default => throw new DecryptException('The only supported ciphers are AES-256-GCM and XChaCha20-Poly1305.'),
        };

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $decrypted;
    }
}
