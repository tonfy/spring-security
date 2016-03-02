/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.scrypt;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.UUID;

import org.junit.Test;

/**
 * @author Shazin Sadakath
 *
 */
public class SCryptPasswordEncoderTests {

    @Test
    public void matches() {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        String result = encoder.encode("password");
        assertFalse(result.equals("password"));
        assertTrue(encoder.matches("password", result));
    }

    @Test
    public void unicode() {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        String result = encoder.encode("passw\u9292rd");
        assertFalse(encoder.matches("pass\u9292\u9292rd", result));
        assertTrue(encoder.matches("passw\u9292rd", result));
    }

    @Test
    public void notMatches() {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        String result = encoder.encode("password");
        assertFalse(encoder.matches("bogus", result));
    }
    
    @Test
    public void customParameters() {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder(UUID.randomUUID().toString(), 512, 8, 4);
        String result = encoder.encode("password");
        assertFalse(result.equals("password"));
        assertTrue(encoder.matches("password", result));
    }

    @Test
    public void doesntMatchNullEncodedValue() {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        assertFalse(encoder.matches("password", null));
    }

    @Test
    public void doesntMatchEmptyEncodedValue() {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        assertFalse(encoder.matches("password", ""));
    }

    @Test
    public void doesntMatchBogusEncodedValue() {
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        assertFalse(encoder.matches("password", "012345678901234567890123456789"));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void invalidSaltParameter() {
        new SCryptPasswordEncoder(null, Integer.MIN_VALUE, 16, 2);     
    } 
    
    @Test(expected = IllegalArgumentException.class)
    public void invalidCpuCostParameter() {
        new SCryptPasswordEncoder(UUID.randomUUID().toString(), Integer.MIN_VALUE, 16, 2);     
    }   
    
    @Test(expected = IllegalArgumentException.class)
    public void invalidMemoryCostParameter() {
        new SCryptPasswordEncoder(UUID.randomUUID().toString(), 2, Integer.MAX_VALUE, 2);     
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void invalidParallelizationParameter() {
        new SCryptPasswordEncoder(UUID.randomUUID().toString(), 2, 8, Integer.MAX_VALUE);     
    }

}

