<?php

namespace Smakecloud\Sodium\Contracts;

interface StringSigner
{
    /**
     * Sign the given string.
     *
     * @param  mixed  $value
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\SignException
     */
    public function signString($value);

    /**
     * Verify the given signed value.
     *
     * @param  string  $signedValue
     * @return mixed
     *
     * @throws \Smakecloud\Sodium\Exceptions\VerifyException
     */
    public function verifyString($signedValue);

    /**
     * Sign the given string in detached mode.
     *
     * @param  mixed  $value
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\SignException
     */
    public function signStringDetached($value);

    /**
     * Verify the given signed string in detached mode.
     *
     * @param  string  $signature
     * @param  string  $value
     * @return bool
     */
    public function verifyStringDetached($signature, $value);

    /**
     * Get the public key.
     *
     * @return string
     */
    public function getPublicKey();

    /**
     * Get the secret key.
     *
     * @return string
     */
    public function getSecretKey();
}
