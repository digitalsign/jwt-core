<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util;

use InvalidArgumentException;
use Jose\Component\Core\JWK;

/**
 * @internal
 */
class KeyChecker
{
    public static function checkKeyUsage(JWK $key, $usage)
    {
        if ($key->has('use')) {
            self::checkUsage($key, $usage);
        }
        if ($key->has('key_ops')) {
            self::checkOperation($key, $usage);
        }
    }
    public static function checkKeyAlgorithm(JWK $key, $algorithm)
    {
        if (!$key->has('alg')) {
            return;
        }
        if ($key->get('alg') !== $algorithm) {
            throw new InvalidArgumentException(sprintf('Key is only allowed for algorithm "%s".', $key->get('alg')));
        }
    }
    private static function checkOperation(JWK $key, $usage)
    {
        $ops = $key->get('key_ops');
        if (!\is_array($ops)) {
            throw new InvalidArgumentException('Invalid key parameter "key_ops". Should be a list of key operations');
        }
        switch ($usage) {
            case 'verification':
                if (!\in_array('verify', $ops, true)) {
                    throw new InvalidArgumentException('Key cannot be used to verify a signature');
                }
                break;
            case 'signature':
                if (!\in_array('sign', $ops, true)) {
                    throw new InvalidArgumentException('Key cannot be used to sign');
                }
                break;
            case 'encryption':
                if (!\in_array('encrypt', $ops, true) && !\in_array('wrapKey', $ops, true) && !\in_array('deriveKey', $ops, true)) {
                    throw new InvalidArgumentException('Key cannot be used to encrypt');
                }
                break;
            case 'decryption':
                if (!\in_array('decrypt', $ops, true) && !\in_array('unwrapKey', $ops, true) && !\in_array('deriveBits', $ops, true)) {
                    throw new InvalidArgumentException('Key cannot be used to decrypt');
                }
                break;
            default:
                throw new InvalidArgumentException('Unsupported key usage.');
        }
    }
    private static function checkUsage(JWK $key, $usage)
    {
        $use = $key->get('use');
        switch ($usage) {
            case 'verification':
            case 'signature':
                if ('sig' !== $use) {
                    throw new InvalidArgumentException('Key cannot be used to sign or verify a signature.');
                }
                break;
            case 'encryption':
            case 'decryption':
                if ('enc' !== $use) {
                    throw new InvalidArgumentException('Key cannot be used to encrypt or decrypt.');
                }
                break;
            default:
                throw new InvalidArgumentException('Unsupported key usage.');
        }
    }
}
