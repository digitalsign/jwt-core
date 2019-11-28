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

use Base64Url\Base64Url;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use RuntimeException;

/**
 * @internal
 */
class ECKey
{
    public static function convertToPEM(JWK $jwk)
    {
        if ($jwk->has('d')) {
            return self::convertPrivateKeyToPEM($jwk);
        }
        return self::convertPublicKeyToPEM($jwk);
    }
    public static function convertPublicKeyToPEM(JWK $jwk)
    {
        switch ($jwk->get('crv')) {
            case 'P-256':
                $der = self::p256PublicKey();
                break;
            case 'P-384':
                $der = self::p384PublicKey();
                break;
            case 'P-521':
                $der = self::p521PublicKey();
                break;
            default:
                throw new InvalidArgumentException('Unsupported curve.');
        }
        $der .= self::getKey($jwk);
        $pem = '-----BEGIN PUBLIC KEY-----' . PHP_EOL;
        $pem .= chunk_split(base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END PUBLIC KEY-----' . PHP_EOL;
        return $pem;
    }
    public static function convertPrivateKeyToPEM(JWK $jwk)
    {
        switch ($jwk->get('crv')) {
            case 'P-256':
                $der = self::p256PrivateKey($jwk);
                break;
            case 'P-384':
                $der = self::p384PrivateKey($jwk);
                break;
            case 'P-521':
                $der = self::p521PrivateKey($jwk);
                break;
            default:
                throw new InvalidArgumentException('Unsupported curve.');
        }
        $der .= self::getKey($jwk);
        $pem = '-----BEGIN EC PRIVATE KEY-----' . PHP_EOL;
        $pem .= chunk_split(base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END EC PRIVATE KEY-----' . PHP_EOL;
        return $pem;
    }
    /**
     * Creates a EC key with the given curve and additional values.
     *
     * @param string $curve  The curve
     * @param array  $values values to configure the key
     */
    public static function createECKey($curve, array $values = [])
    {
        $jwk = self::createECKeyUsingOpenSSL($curve);
        $values = array_merge($values, $jwk);
        return new JWK($values);
    }
    private static function getNistCurveSize($curve)
    {
        switch ($curve) {
            case 'P-256':
                return 256;
            case 'P-384':
                return 384;
            case 'P-521':
                return 521;
            default:
                throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve));
        }
    }
    private static function createECKeyUsingOpenSSL($curve)
    {
        $key = openssl_pkey_new(['curve_name' => self::getOpensslCurveName($curve), 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        if (false === $key) {
            throw new RuntimeException('Unable to create the key');
        }
        $result = openssl_pkey_export($key, $out);
        if (false === $result) {
            throw new RuntimeException('Unable to create the key');
        }
        $res = openssl_pkey_get_private($out);
        if (false === $res) {
            throw new RuntimeException('Unable to create the key');
        }
        $details = openssl_pkey_get_details($res);
        $nistCurveSize = self::getNistCurveSize($curve);
        return ['kty' => 'EC', 'crv' => $curve, 'd' => Base64Url::encode(str_pad($details['ec']['d'], (int) ceil($nistCurveSize / 8), "\0", STR_PAD_LEFT)), 'x' => Base64Url::encode(str_pad($details['ec']['x'], (int) ceil($nistCurveSize / 8), "\0", STR_PAD_LEFT)), 'y' => Base64Url::encode(str_pad($details['ec']['y'], (int) ceil($nistCurveSize / 8), "\0", STR_PAD_LEFT))];
    }
    private static function getOpensslCurveName($curve)
    {
        switch ($curve) {
            case 'P-256':
                return 'prime256v1';
            case 'P-384':
                return 'secp384r1';
            case 'P-521':
                return 'secp521r1';
            default:
                throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve));
        }
    }
    private static function p256PublicKey()
    {
        return pack('H*', '3059' . '3013' . '0607' . '2a8648ce3d0201' . '0608' . '2a8648ce3d030107' . '0342' . '00');
    }
    private static function p384PublicKey()
    {
        return pack('H*', '3076' . '3010' . '0607' . '2a8648ce3d0201' . '0605' . '2b81040022' . '0362' . '00');
    }
    private static function p521PublicKey()
    {
        return pack('H*', '30819b' . '3010' . '0607' . '2a8648ce3d0201' . '0605' . '2b81040023' . '038186' . '00');
    }
    private static function p256PrivateKey(JWK $jwk)
    {
        $d = unpack('H*', str_pad(Base64Url::decode($jwk->get('d')), 32, "\0", STR_PAD_LEFT))[1];
        return pack('H*', '3077' . '020101' . '0420' . $d . 'a00a' . '0608' . '2a8648ce3d030107' . 'a144' . '0342' . '00');
    }
    private static function p384PrivateKey(JWK $jwk)
    {
        $d = unpack('H*', str_pad(Base64Url::decode($jwk->get('d')), 48, "\0", STR_PAD_LEFT))[1];
        return pack('H*', '3081a4' . '020101' . '0430' . $d . 'a007' . '0605' . '2b81040022' . 'a164' . '0362' . '00');
    }
    private static function p521PrivateKey(JWK $jwk)
    {
        $d = unpack('H*', str_pad(Base64Url::decode($jwk->get('d')), 66, "\0", STR_PAD_LEFT))[1];
        return pack('H*', '3081dc' . '020101' . '0442' . $d . 'a007' . '0605' . '2b81040023' . 'a18189' . '038186' . '00');
    }
    private static function getKey(JWK $jwk)
    {
        $nistCurveSize = self::getNistCurveSize($jwk->get('crv'));
        $length = (int) ceil($nistCurveSize / 8);
        return "\4" . str_pad(Base64Url::decode($jwk->get('x')), $length, "\0", STR_PAD_LEFT) . str_pad(Base64Url::decode($jwk->get('y')), $length, "\0", STR_PAD_LEFT);
    }
}
