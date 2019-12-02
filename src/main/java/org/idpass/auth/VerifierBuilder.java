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

import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacardx.biometry.BioBuilder;

final class VerifierBuilder {
    public static final byte PIN         = Utils.BYTE_00;
    public static final byte FINGERPRINT = (byte) 0x03;

    private static final byte DEFAULT_TRY_LIMIT = (byte) 10;

    static Verifier createVerifier(byte verifierType, byte[] buffer, short offset, short length) {
        switch (verifierType) {
            case PIN:
                return createPinVerifier(buffer, offset, length);
            case FINGERPRINT:
                return createFingerprintBioVerifier(buffer, offset, length);
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return null;
    }

    static PinVerifier createPinVerifier(byte[] buffer, short offset, short length) {
        return new PinVerifier(buffer, offset, length);
    }

    
    static BioVerifier createFingerprintBioVerifier(byte[] buffer, short offset, short length) {
        BioVerifier result = null;
        try {
            result = new BioVerifier(BioBuilder.FINGERPRINT, DEFAULT_TRY_LIMIT, buffer, offset, length);
        } catch (CardRuntimeException e) {
            ISOException.throwIt(e.getReason());
        }
        
        return result;
    }

    private VerifierBuilder() {
    }
}
