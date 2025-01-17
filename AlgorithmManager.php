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

use InvalidArgumentException;

class AlgorithmManager
{
    /**
     * @var array
     */
    private $algorithms = [];
    /**
     * @param Algorithm[] $algorithms
     */
    public function __construct(array $algorithms)
    {
        foreach ($algorithms as $algorithm) {
            $this->add($algorithm);
        }
    }
    /**
     * Returns true if the algorithm is supported.
     *
     * @param string $algorithm The algorithm
     */
    public function has($algorithm)
    {
        return \array_key_exists($algorithm, $this->algorithms);
    }
    /**
     * Returns the list of names of supported algorithms.
     *
     * @return string[]
     */
    public function list()
    {
        return array_keys($this->algorithms);
    }
    /**
     * Returns the algorithm if supported, otherwise throw an exception.
     *
     * @param string $algorithm The algorithm
     */
    public function get($algorithm)
    {
        if (!$this->has($algorithm)) {
            throw new InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $algorithm));
        }
        return $this->algorithms[$algorithm];
    }
    /**
     * Adds an algorithm to the manager.
     */
    private function add(Algorithm $algorithm)
    {
        $name = $algorithm->name();
        $this->algorithms[$name] = $algorithm;
    }
}
