<?php

namespace Smakecloud\Sodium\Contracts;

interface Signer
{
    /**
     * Sign the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\SignException
     */
    public function sign($value, $serialize = true);

    /**
     * Verify the given signed value.
     *
     * @param  string  $signedValue
     * @param  bool  $unserialize
     * @return mixed
     *
     * @throws \Smakecloud\Sodium\Exceptions\VerifyException
     */
    public function verify($signedValue, $unserialize = true);

    /**
     * Sign the given value in detached mode.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     *
     * @throws \Smakecloud\Sodium\Exceptions\SignException
     */
    public function signDetached($value, $serialize = true);

    /**
     * Verify the given signed value in detached mode.
     *
     * @param  string  $signature
     * @param  string  $value
     * @param  bool  $unserialize
     * @return bool
     */
    public function verifyDetached($signature, $value, $unserialize = true);

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
