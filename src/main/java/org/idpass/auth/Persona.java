/*
 * Copyright (C) 2019 Newlogic Impact Lab Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.idpass.auth;

import org.idpass.tools.Utils;

import javacard.framework.JCSystem;

/**
 * Persona class
 *
 */
final class Persona {

    static final short         DEFAULT_VERIFIERS_COUNT    = 1;

    private static final short AUTHENTICATED_ARRAY_LENGTH = 1;
    private static final short AUTHENTICATED_INDEX        = 0;

    private Verifier[]         verifiers;
    private boolean[]          authenticated;

    /**
     * New persona constructor
     */
    public Persona() {
        verifiers = new Verifier[DEFAULT_VERIFIERS_COUNT];
        authenticated = JCSystem.makeTransientBooleanArray(AUTHENTICATED_ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
    }

    public boolean isVerifierExists(short index) {
        return !(verifiers.length <= index || verifiers[index] == null);
    }

    /**
     * verify persona
     * 
     * @param buffer
     * @param offset
     * @param length
     * @return verification result
     */
    public short verify(byte[] buffer, short offset, short length) {
        short result = -1;
        VerificationResult verificationResult = null;
        for (short i = 0; i < verifiers.length; i++) {
            if (!isVerifierExists(i))
                continue;
            verificationResult = verifiers[i].verify(buffer, offset, length);
            if (verificationResult.success) {
                setAuthenticated();
                result = verificationResult.score;
                break;
            }
        }

        return result;
    }
    
    public boolean isAuthenticated() {
        return authenticated[AUTHENTICATED_INDEX];
    }

    /**
     * deleteVerifier for persona
     * 
     * @param index
     * @return true in case success
     */
    public boolean deleteVerifierByIndex(short index) {
        if (verifiers.length <= index)
            return false;

        if (verifiers[index] == null) {
            return true;
        }

        verifiers[index] = null;
        Utils.requestObjectDeletion();
        return true;
    }

    /**
     * addVerifier for persona
     * 
     * @param verifier
     * @return index
     */
    public short addVerifier(Verifier verifier) {
        short newIndex = 0;
        boolean foundNewItem = false;
        for (short i = 0; i < verifiers.length; i++) {
            if (verifiers[i] == null) {
                newIndex = i;
                foundNewItem = true;
                break;
            }
        }

        if (!foundNewItem) {
            short extendCount = 1;
            extend(extendCount);
            newIndex = (short) (verifiers.length - extendCount);
        }

        verifiers[newIndex] = verifier;
        return newIndex;
    }

    private void extend(short extendCount) {
        Verifier[] arr = new Verifier[(short) (verifiers.length + extendCount)];
        for (short i = 0; i < verifiers.length; i++) {
            arr[i] = verifiers[i];
        }

        verifiers = arr;
        Utils.requestObjectDeletion();
    }
    
    private void setAuthenticated() {
        authenticated[AUTHENTICATED_INDEX] = true;
    }

}
