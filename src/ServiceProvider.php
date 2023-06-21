<?php

namespace Smakecloud\Sodium;

use Illuminate\Encryption\MissingAppKeyException;
use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;
use Illuminate\Support\Str;
use Smakecloud\Sodium\Encryption\Encrypter;
use Smakecloud\Sodium\Signing\Signer;

class ServiceProvider extends IlluminateServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->singleton(Encrypter::class, function ($app) {
            $config = $app->make('config')->get('app');

            return new Encrypter($this->parseKey($config), $config['cipher']);
        });
        $this->app->alias(Encrypter::class, 'encrypter');

        $this->app->singleton(Signer::class, function ($app) {
            $config = $app->make('config')->get('app');

            return new Signer($this->parseKey($config));
        });
        $this->app->alias(Signer::class, 'signer');
    }

    /**
     * Parse the encryption key.
     *
     * @param  array<mixed>  $config
     *
     * @throws \Illuminate\Encryption\MissingAppKeyException
     */
    protected function parseKey(array $config): string
    {
        $key = $this->key($config);

        if (! is_string($key)) {
            throw new MissingAppKeyException();
        }

        if (Str::startsWith($key, $prefix = 'base64:')) {
            $key = base64_decode(Str::after($key, $prefix));
        }

        return $key;
    }

    /**
     * Get the encryption key.
     *
     * @param  array<mixed>  $config
     *
     * @throws \Illuminate\Encryption\MissingAppKeyException
     */
    protected function key(array $config): mixed
    {
        return tap($config['key'], function ($key) {
            if (empty($key)) {
                throw new MissingAppKeyException();
            }
        });
    }
}
