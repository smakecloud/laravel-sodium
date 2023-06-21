<?php

namespace Tests\Signing;

use RuntimeException;
use Smakecloud\Sodium\Signing\Signer;
use Tests\TestCase;

class SignerTest extends TestCase
{
    /** @test */
    public function it_throws_an_exception_for_an_invalid_seed_size()
    {
        $this->expectException(RuntimeException::class);

        new Signer(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES + 1));
    }

    /** @test */
    public function it_generates_a_keypair()
    {
        $keyPair = Signer::generateKeyPair();

        $this->assertEquals(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES + SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, mb_strlen($keyPair, '8bit'));
    }

    /** @test */
    public function it_generates_a_seeded_keypair()
    {
        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $keyPair1 = Signer::generateKeyPair($seed);
        $keyPair2 = Signer::generateKeyPair($seed);

        $this->assertEquals(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES + SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, mb_strlen($keyPair1, '8bit'));
        $this->assertEquals($keyPair1, $keyPair2);
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_generate_a_keypair_with_an_invalid_seed_length()
    {
        $this->expectException(RuntimeException::class);

        Signer::generateKeyPair(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES + 1));
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_sign_unserialized_data()
    {
        $signer = new Signer(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));

        $this->expectException(\Smakecloud\Sodium\Exceptions\SignException::class);

        $signer->sign(['my msg to be signed'], false);
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_sign_unserialized_data_in_detached_mode()
    {
        $signer = new Signer(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));

        $this->expectException(\Smakecloud\Sodium\Exceptions\SignException::class);

        $signer->signDetached(['my msg to be signed'], false);
    }

    /** @test */
    public function it_throws_an_exception_when_verifying_an_invalid_signature()
    {
        $signer = new Signer(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));

        $this->expectException(\Smakecloud\Sodium\Exceptions\VerifyException::class);

        $signer->verify('invalid signature');
    }

    /** @test */
    public function it_can_sign_and_verify_a_value()
    {
        $signer = new Signer(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));

        $signedMessage = $signer->sign('my msg to be signed');

        $this->assertEquals($signer->verify($signedMessage), 'my msg to be signed');
    }

    /** @test */
    public function it_can_sign_and_verify_a_value_in_detach_mode()
    {
        $signer = new Signer(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));

        $signature = $signer->signDetached('my msg to be signed');

        $this->assertTrue($signer->verifyDetached($signature, 'my msg to be signed'));
    }

    /** @test */
    public function it_can_sign_and_verify_a_string()
    {
        $signer = new Signer(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));

        $signedMessage = $signer->signString('my msg to be signed');

        $this->assertEquals($signer->verifyString($signedMessage), 'my msg to be signed');
    }

    /** @test */
    public function it_can_sign_and_verify_a_string_in_detached_mode()
    {
        $signer = new Signer(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));

        $signature = $signer->signStringDetached('my msg to be signed');

        $this->assertEquals($signer->verifyStringDetached($signature, 'my msg to be signed'), 'my msg to be signed');
    }

    /** @test */
    public function it_can_sign_and_verify_a_value_using_the_helper()
    {
        $signed = sign('my msg to be signed');

        $this->assertNotEquals('my msg to be signed', $signed);

        $this->assertEquals('my msg to be signed', verify($signed));
    }

    /** @test */
    public function it_can_sign_and_verify_a_value_using_the_helper_in_detached_mode()
    {
        $signature = sign_detached('my msg to be signed');

        $this->assertTrue(verify_detached($signature, 'my msg to be signed'));
    }

    /** @test */
    public function it_can_sign_and_verify_a_string_using_the_helper()
    {
        $signed = sign_string('my msg to be signed');

        $this->assertNotEquals('my msg to be signed', $signed);

        $this->assertEquals('my msg to be signed', verify_string($signed));
    }

    /** @test */
    public function it_can_sign_and_verify_a_string_using_the_helper_in_detached_mode()
    {
        $signature = sign_string_detached('my msg to be signed');

        $this->assertEquals('my msg to be signed', verify_string_detached($signature, 'my msg to be signed'));
    }
}
