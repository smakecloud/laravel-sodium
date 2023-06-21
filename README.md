# Laravel Sodium

Uses [PHP's Sodium](https://www.php.net/manual/en/book.sodium.php) extension to encrypt, decrypt, sign and verify data.

**This package overrides Laravel's Encrypter class!**
You will lose support for the following ciphers:
- AES-128-CBC
- AES-256-CBC
- AES-128-GCM

Supported encryption ciphers are:
- [XCha-Cha20-Poly1305](https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php)
- [AES-256-GCM](https://www.php.net/manual/en/function.sodium-crypto-aead-aes256gcm-encrypt.php)

Supported signing algorithms are:
- [Ed25519](https://www.php.net/manual/en/function.sodium-crypto-sign.php)

Signing KeyPair is generated using the `APP_KEY` environment variable as seed.
See [sodium_crypto_sign_seed_keypair](https://www.php.net/manual/en/function.sodium-crypto-sign-seed-keypair.php)

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Development](#development)
  - [Testing](#testing)
  - [Coverage](#coverage)
  - [Static analysis](#static-analysis)
  - [Code style](#code-style)
- [License](#license)

## Requirements

- PHP 8.1+
- Sodium extension ( obviously )

## Installation

You can install the package via composer:

```bash
composer require smakecloud/laravel-sodium
```

This package uses Laravel's auto-discovery feature. After you install it the package provider and facade are available immediately.

## Usage

This package overrides Laravel's Encrypter class. You can use it as you would use the default Encrypter class.

You can change the default cipher in:

`config/app.php`

```php
return [
    //...

    'cipher' => 'XCha-Cha20-Poly1305',

    //...
]
```

```php
$encrypted = encrypt('secret');
$decrypted = decrypt($encrypted); // 'secret'

$signed = sign('secret');
$verified = verify($signed); // 'secret'

$signature = sign_detached('secret');
$verified = verify_detached($signature, 'secret'); // true
```

## Development

### Testing

```bash
composer test
```

### Coverage

```bash
composer test:coverage
```

### Static analysis

```bash
composer phpstan
```

### Code style

```bash
composer lint(:fix)
```

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
