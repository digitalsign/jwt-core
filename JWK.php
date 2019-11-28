<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

use Base64Url\Base64Url;
use InvalidArgumentException;
use JsonSerializable;

class JWK implements JsonSerializable
{
    /**
     * @var array
     */
    private $values = [];
    /**
     * Creates a JWK object using the given values.
     * The member "kty" is mandatory. Other members are NOT checked.
     */
    public function __construct(array $values)
    {
        if (!isset($values['kty'])) {
            throw new InvalidArgumentException('The parameter "kty" is mandatory.');
        }
        $this->values = $values;
    }
    /**
     * Creates a JWK object using the given Json string.
     *
     * @return JWK
     */
    public static function createFromJson($json)
    {
        $data = json_decode($json, true);
        if (!\is_array($data)) {
            throw new InvalidArgumentException('Invalid argument.');
        }
        return new self($data);
    }
    /**
     * Returns the values to be serialized.
     */
    public function jsonSerialize()
    {
        return $this->values;
    }
    /**
     * Get the value with a specific key.
     *
     * @param string $key The key
     *
     * @return null|mixed
     */
    public function get($key)
    {
        if (!$this->has($key)) {
            throw new InvalidArgumentException(sprintf('The value identified by "%s" does not exist.', $key));
        }
        return $this->values[$key];
    }
    /**
     * Returns true if the JWK has the value identified by.
     *
     * @param string $key The key
     */
    public function has($key)
    {
        return \array_key_exists($key, $this->values);
    }
    /**
     * Get all values stored in the JWK object.
     *
     * @return array Values of the JWK object
     */
    public function all()
    {
        return $this->values;
    }
    /**
     * Returns the thumbprint of the key.
     *
     * @see https://tools.ietf.org/html/rfc7638
     */
    public function thumbprint($hash_algorithm)
    {
        if (!\in_array($hash_algorithm, hash_algos(), true)) {
            throw new InvalidArgumentException(sprintf('The hash algorithm "%s" is not supported.', $hash_algorithm));
        }
        $values = array_intersect_key($this->values, array_flip(['kty', 'n', 'e', 'crv', 'x', 'y', 'k']));
        ksort($values);
        $input = json_encode($values, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return Base64Url::encode(hash($hash_algorithm, $input, true));
    }
    /**
     * Returns the associated public key.
     * This method has no effect for:
     * - public keys
     * - shared keys
     * - unknown keys.
     *
     * Known keys are "oct", "RSA", "EC" and "OKP".
     *
     * @return JWK
     */
    public function toPublic()
    {
        $values = array_diff_key($this->values, array_flip(['p', 'd', 'q', 'dp', 'dq', 'qi']));
        return new self($values);
    }
}
