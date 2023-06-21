<?php

// @codeCoverageIgnoreStart
if (! function_exists('sign')) {
    // @codeCoverageIgnoreEnd
    /**
     * Sign the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     */
    function sign($value, $serialize = true)
    {
        return app('signer')->sign($value, $serialize);
    }
}

// @codeCoverageIgnoreStart
if (! function_exists('verify')) {
    // @codeCoverageIgnoreEnd
    /**
     * Verify the given signed value.
     *
     * @param  string  $signedValue
     * @param  bool  $unserialize
     * @return mixed
     */
    function verify($signedValue, $unserialize = true)
    {
        return app('signer')->verify($signedValue, $unserialize);
    }
}

// @codeCoverageIgnoreStart
if (! function_exists('sign_string')) {
    // @codeCoverageIgnoreEnd
    /**
     * Sign the given string.
     *
     * @param  string  $value
     * @return string
     */
    function sign_string($value)
    {
        return app('signer')->signString($value);
    }
}

// @codeCoverageIgnoreStart
if (! function_exists('verify_string')) {
    // @codeCoverageIgnoreEnd
    /**
     * Verify the given signed string.
     *
     * @param  string  $signedValue
     * @return string
     */
    function verify_string($signedValue)
    {
        return app('signer')->verifyString($signedValue);
    }
}

// @codeCoverageIgnoreStart
if (! function_exists('sign_detached')) {
    // @codeCoverageIgnoreEnd
    /**
     * Sign the given value in detached mode.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     * @return string
     */
    function sign_detached($value, $serialize = true)
    {
        return app('signer')->signDetached($value, $serialize);
    }
}

// @codeCoverageIgnoreStart
if (! function_exists('verify_detached')) {
    // @codeCoverageIgnoreEnd
    /**
     * Verify the given signed value in detached mode.
     *
     * @param  string  $signature
     * @param  mixed  $value
     * @param  bool  $unserialize
     * @return bool
     */
    function verify_detached($signature, $value, $unserialize = true)
    {
        return app('signer')->verifyDetached($signature, $value, $unserialize);
    }
}

// @codeCoverageIgnoreStart
if (! function_exists('sign_string_detached')) {
    // @codeCoverageIgnoreEnd
    /**
     * Sign the given string in detached mode.
     *
     * @param  string  $value
     * @return string
     */
    function sign_string_detached($value)
    {
        return app('signer')->signStringDetached($value);
    }
}

// @codeCoverageIgnoreStart
if (! function_exists('verify_string_detached')) {
    // @codeCoverageIgnoreEnd
    /**
     * Verify the given signed string in detached mode.
     *
     * @param  string  $signature
     * @param  string  $value
     * @return bool
     */
    function verify_string_detached($signature, $value)
    {
        return app('signer')->verifyStringDetached($signature, $value);
    }
}
