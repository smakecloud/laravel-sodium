<?php

namespace Smakecloud\Sodium\Signing;

use Smakecloud\Sodium\Contracts\Signer as SignerContract;
use Smakecloud\Sodium\Contracts\StringSigner;
use Smakecloud\Sodium\Exceptions\SignException;
use Smakecloud\Sodium\Exceptions\VerifyException;

class Signer implements SignerContract, StringSigner
{
    /**
     * The signing key pair.
     *
     * @var non-empty-string
     */
    protected $keyPair;

    /**
     * Create a new signer instance.
     *
     * @param  string  $key
     * @return void
     *
     * @throws \RuntimeException
     */
    public function __construct($key)
    {
        if (! static::supported($key)) {
            throw new \RuntimeException('Unsupported key length. Expected '.SODIUM_CRYPTO_SIGN_SEEDBYTES.' bytes.');
        }

        $this->keyPair = self::generateKeyPair($key);
    }

    /**
     * Determine if the given key is a valid sodium sign keypair seed
     *
     * @param  string  $key
     * @return bool
     */
    public static function supported($key)
    {
        return mb_strlen($key, '8bit') === SODIUM_CRYPTO_SIGN_SEEDBYTES;
    }

    /**
     * Generate a new key pair.
     *
     * @param  string|null  $seed
     * @return non-empty-string
     *
     * @throws \RuntimeException
     */
    public static function generateKeyPair($seed = null)
    {
        if ($seed === null) {
            return sodium_crypto_sign_keypair();
        }

        if (empty($seed)) {
            throw new \RuntimeException('Seed cannot be empty.');
        }

        if (! static::supported($seed)) {
            throw new \RuntimeException('Unsupported key length. Expected '.SODIUM_CRYPTO_SIGN_SEEDBYTES.' bytes.');
        }

        return sodium_crypto_sign_seed_keypair($seed);
    }

    /**
     * Sign the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\SignException
     */
    public function sign($value, $serialize = true)
    {
        $value = $serialize ? serialize($value) : $value;

        if (! is_string($value)) {
            throw new SignException('The value to sign must be a string.');
        }

        try {
            $signedMessage = sodium_crypto_sign(
                $value,
                $this->getSecretKey()
            );
        } catch (\Throwable $e) {
            throw new SignException('Could not sign the data.', 0, $e);
        }

        return base64_encode($signedMessage);
    }

    /**
     * Verify the given signed message.
     *
     * @param  string  $signedMessage
     * @param  bool  $unserialize
     * @return mixed
     *
     * @throws \Smakecloud\Sodium\Exceptions\VerifyException
     */
    public function verify($signedMessage, $unserialize = true)
    {
        $verified = sodium_crypto_sign_open(
            base64_decode($signedMessage),
            $this->getPublicKey()
        );

        if (! $verified) {
            throw new VerifyException('The signature is invalid.');
        }

        return $unserialize ? unserialize($verified) : $verified;
    }

    /**
     * Sign the given string.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\SignException
     */
    public function signString($value)
    {
        return $this->sign($value, false);
    }

    /**
     * Verify the given signed string.
     *
     * @param  string  $signedString
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\VerifyException
     */
    public function verifyString($signedString)
    {
        $verifiedString = $this->verify($signedString, false);

        if (! is_string($verifiedString)) {
            throw new VerifyException('The signature is invalid.');
        }

        return $verifiedString;
    }

    /**
     * Sign the given value and return a detached signature.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\SignException
     */
    public function signDetached($value, $serialize = true)
    {
        $value = $serialize ? serialize($value) : $value;

        if (! is_string($value)) {
            throw new SignException('The value to sign must be a string.');
        }

        try {
            $signature = sodium_crypto_sign_detached(
                $value,
                $this->getSecretKey()
            );
        } catch (\Throwable $e) {
            throw new SignException('Could not sign the data.', 0, $e);
        }

        return base64_encode($signature);
    }

    /**
     * Verify the given detached signature.
     *
     * @param  string  $signature
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return bool
     */
    public function verifyDetached($signature, $value, $serialize = true)
    {
        $message = $serialize ? serialize($value) : $value;

        if (! is_string($message)) {
            return false;
        }

        $decodedSignature = base64_decode($signature);

        if (empty($decodedSignature) || mb_strlen($decodedSignature, '8bit') !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached(
            $decodedSignature,
            $message,
            $this->getPublicKey()
        );
    }

    /**
     * Sign the given string and return a detached signature.
     *
     * @param  string  $value
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\SignException
     */
    public function signStringDetached($value)
    {
        return $this->signDetached($value, false);
    }

    /**
     * Verify the given detached string signature.
     *
     * @param  string  $signature
     * @param  string  $value
     * @return bool
     */
    public function verifyStringDetached($signature, $value)
    {
        return $this->verifyDetached($signature, $value, false);
    }

    /**
     * Get the secret key.
     *
     * @return non-empty-string
     */
    public function getSecretKey()
    {
        return sodium_crypto_sign_secretkey($this->keyPair);
    }

    /**
     * Get the public key.
     *
     * @return non-empty-string
     */
    public function getPublicKey()
    {
        return sodium_crypto_sign_publickey($this->keyPair);
    }
}
