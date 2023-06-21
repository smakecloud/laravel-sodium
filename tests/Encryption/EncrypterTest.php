<?php

namespace Tests\Encryption;

use RuntimeException;
use Smakecloud\Sodium\Encryption\Encrypter;
use Tests\TestCase;

class EncrypterTest extends TestCase
{
    protected function usesAES256GCMCipher($app)
    {
        $app->config->set('app.cipher', 'AES-256-GCM');
    }

    protected function usesXchaCha20Poly1305Cipher($app)
    {
        $app->config->set('app.cipher', 'XCHA-CHA20-POLY1305');
    }

    /** @test */
    public function it_can_be_created_with_a_valid_key()
    {
        $encrypter = new Encrypter(random_bytes(32));

        $this->assertInstanceOf(Encrypter::class, $encrypter);
    }

    /** @test */
    public function it_returns_the_key()
    {
        $key = random_bytes(32);
        $encrypter = new Encrypter($key);

        $this->assertEquals($key, $encrypter->getKey());
    }

    /** @test */
    public function it_throws_an_exception_for_an_unspupported_cipher()
    {
        $this->expectException(RuntimeException::class);

        new Encrypter(random_bytes(32), 'AES-256-CBC');
    }

    /**
     * @test
     *
     * @define-env usesAES256GCMCipher
     */
    public function it_throws_an_exception_for_an_unspupported_key_length_using_aes256()
    {
        $this->expectException(RuntimeException::class);

        new Encrypter(random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES + 1));
    }

    /**
     * @test
     *
     * @define-env usesXchaCha20Poly1305Cipher
     */
    public function it_throws_an_exception_for_an_unspupported_key_length_using_xchacha20()
    {
        $this->expectException(RuntimeException::class);

        new Encrypter(random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES + 1));
    }

    /** @test */
    public function it_can_generate_a_random_key()
    {
        $key = Encrypter::generateKey('AES-256-GCM');

        $this->assertEquals(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES, mb_strlen($key, '8bit'));
    }

    /**
     * @test
     *
     * @define-env usesAES256GCMCipher
     */
    public function it_throws_an_exception_when_trying_to_encrypt_non_string_values_without_serializing()
    {
        $encrypter = new Encrypter(Encrypter::generateKey('AES-256-GCM'));

        $this->expectException(\Illuminate\Contracts\Encryption\EncryptException::class);

        $encrypter->encrypt(['foo'], false);
    }

    /**
     * @test
     *
     * @define-env usesAES256GCMCipher
     */
    public function it_throws_an_exception_when_trying_to_decrypt_non_string_values_without_serializing()
    {
        $encrypter = new Encrypter(Encrypter::generateKey('AES-256-GCM'));

        $this->expectException(\Illuminate\Contracts\Encryption\DecryptException::class);

        $encrypter->decrypt(['foo'], false);
    }

    /**
     * @test
     *
     * @define-env usesAES256GCMCipher
     */
    public function it_throws_an_exception_with_an_invalid_payload()
    {
        $encrypter = new Encrypter(Encrypter::generateKey('AES-256-GCM'));
        $payload = base64_encode(json_encode([
            'encrypted' => 'foo',
        ]));

        $this->expectException(\Illuminate\Contracts\Encryption\DecryptException::class);

        $encrypter->decrypt($payload);
    }

    /**
     * @test
     *
     * @define-env usesAES256GCMCipher
     */
    public function it_can_encrypt_and_decrypt_a_value_usign_aes256()
    {
        $encrypter = new Encrypter(Encrypter::generateKey('AES-256-GCM'));

        $encrypted = $encrypter->encrypt('my secret value');

        $this->assertNotEquals('my secret value', $encrypted);

        $this->assertEquals('my secret value', $encrypter->decrypt($encrypted));
    }

    /**
     * @test
     *
     * @define-env usesXchaCha20Poly1305Cipher
     */
    public function it_can_encrypt_and_decrypt_a_value_usign_xchacha20()
    {
        $encrypter = new Encrypter(Encrypter::generateKey('XCHA-CHA20-POLY1305'));

        $encrypted = $encrypter->encrypt('my secret value');

        $this->assertNotEquals('my secret value', $encrypted);

        $this->assertEquals('my secret value', $encrypter->decrypt($encrypted));
    }

    /**
     * @test
     *
     * @define-env usesAES256GCMCipher
     */
    public function it_can_encrypt_and_decrypt_a_value_using_the_helper_with_aes256()
    {
        $encrypted = encrypt('my secret value');

        $this->assertNotEquals('my secret value', $encrypted);

        $this->assertEquals('my secret value', decrypt($encrypted));
    }

    /**
     * @test
     *
     * @define-env usesXchaCha20Poly1305Cipher
     */
    public function it_can_encrypt_and_decrypt_a_value_using_the_helper_with_xchacha20()
    {
        $encrypted = encrypt('my secret value');

        $this->assertNotEquals('my secret value', $encrypted);

        $this->assertEquals('my secret value', decrypt($encrypted));
    }

    /** @test */
    public function it_can_encrypt_and_decrypt_a_string()
    {
        $encrypter = new Encrypter(random_bytes(32));

        $encrypted = $encrypter->encryptString('my secret value');

        $this->assertNotEquals('my secret value', $encrypted);

        $this->assertEquals('my secret value', $encrypter->decryptString($encrypted));
    }
}
