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

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import org.idpass.tools.IdpassApplet;
import org.idpass.tools.SIOAuthListener;
import org.idpass.tools.Utils;

/**
 * AuthApplet
 *
 */
public class AuthApplet extends IdpassApplet {

    private static final byte LENGTH_INSTALL_PARAMS            = 0;

    // default secret for SIO
    private static final byte DEFAULT_SECRET                   = (byte) 0x9E;
    // INS
    // ISO
    // add listener. auth enc
    private static final byte INS_ADD_LISTENER                 = (byte) 0xAA;
    private static final byte P1_ADD_LISTENER                  = (byte) 0x00;
    private static final byte P2_ADD_LISTENER                  = (byte) 0x00;

    // delete listener. auth enc
    private static final byte INS_DELETE_LISTENER              = (byte) 0xDA;
    private static final byte P1_DELETE_LISTENER               = (byte) 0x00;
    private static final byte P2_DELETE_LISTENER               = (byte) 0x00;

    // add persona. auth mac
    private static final byte INS_ADD_PERSONA                  = (byte) 0x1A;
    private static final byte P1_ADD_PERSONA                   = (byte) 0x00;
    private static final byte P2_ADD_PERSONA                   = (byte) 0x00;

    // delete persona (p2 = persona id). auth enc or mac
    private static final byte INS_DELETE_PERSONA               = (byte) 0x1D;
    private static final byte P1_DELETE_PERSONA                = (byte) 0x00;

    // add verifier for persona (p2 = persona id). auth enc
    private static final byte INS_ADD_VERIFIER_FOR_PERSONA     = (byte) 0x2A;
    private static final byte P1_ADD_VERIFIER_FOR_PERSONA      = (byte) 0x00;

    // delete verifier (p1 = persona id, p2 = verifier id). auth enc or mac
    private static final byte INS_DELETE_VERIFIER_FROM_PERSONA = (byte) 0x2D;

    // authenticate persona. no SCP
    private static final byte INS_AUTHENTICATE_PERSONA         = (byte) 0xEF;
    private static final byte P1_UTHENTICATE_PERSONA           = (byte) 0x1D;
    private static final byte P2_UTHENTICATE_PERSONA           = (byte) 0xCD;

    public static void install(byte[] bArray, short bOffset, byte bLength) {

        AuthApplet applet = new AuthApplet(bArray, bOffset, bLength);

        // GP-compliant JavaCard applet registration
        applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    public boolean isPersonaExists(short personaIndex) {
        return personasRepository.exists(personaIndex);
    }

    public void uninstall() {
        super.uninstall();
        personasRepository.reset();
        personasRepository = null;
        listeners = null;
    }

    private PersonasRepository personasRepository;
    private byte               verifierType;
    private byte               secret;
    private AID[]              listeners;

    protected void processSelect() {
        if (!selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        setIncomingAndReceiveUnwrap();

        byte[] buffer = getApduData();

        short length = Util.setShort(buffer, Utils.SHORT_00, personasRepository.getPersonasCount());
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

    protected void processInternal(APDU apdu) throws ISOException {

        switch (this.ins) {
            case INS_ADD_LISTENER:
                checkClaIsInterindustry();
                processAddListener();
                break;
            case INS_DELETE_LISTENER:
                checkClaIsInterindustry();
                processDeleteListener();
                break;
            case INS_ADD_PERSONA:
                checkClaIsInterindustry();
                processAddPersona();
                break;
            case INS_ADD_VERIFIER_FOR_PERSONA:
                checkClaIsInterindustry();
                processAddVerifierForPersona();
                break;
            case INS_DELETE_PERSONA:
                checkClaIsInterindustry();
                processDeletePersona();
                break;
            case INS_DELETE_VERIFIER_FROM_PERSONA:
                checkClaIsInterindustry();
                processDeleteVerifierFromPersona();
                break;
            case INS_AUTHENTICATE_PERSONA:
                checkClaIsInterindustry();
                processAuthenticatePersona();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    protected AuthApplet(byte[] bArray, short bOffset, byte bLength) {
        byte lengthAID = bArray[bOffset];
        short offsetAID = (short) (bOffset + 1);
        short offset = bOffset;
        offset += (bArray[offset]); // skip aid
        offset++;
        offset += (bArray[offset]); // skip privileges
        offset++;

        // default params
        short personaInitCount = 1;
        byte verifierType = VerifierBuilder.FINGERPRINT;
        byte secret = DEFAULT_SECRET;

        // read params
        short lengthIn = bArray[offset];
        if (lengthIn != 0) {
            if (lengthIn < LENGTH_INSTALL_PARAMS) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            if (1 <= lengthIn) {
                // param 1 - not mandatory
                verifierType = bArray[(short) (offset + 1)];
            }

            if (2 <= lengthIn) {
                // param 2 - not mandatory
                personaInitCount = Util.makeShort(Utils.BYTE_00, bArray[(short) (offset + 2)]);
            }
            if (3 <= lengthIn) {
                // param 3 - not mandatory
                secret = bArray[(short) (offset + 3)];
            }
        }

        personasRepository = PersonasRepository.create(personaInitCount);
        this.verifierType = verifierType;
        this.secret = secret;
        this.listeners = new AID[0]; 
    }

    private SIOAuthListener getSIOAuthListener(AID aid) {
        if (aid == null) {
            return null;
        }
        return (SIOAuthListener) JCSystem.getAppletShareableInterfaceObject(aid, secret);
    }

    private void doAfterAddPersona(short personaIndex) {
        for (short i = 0; i < listeners.length; i++) {
            SIOAuthListener listener = getSIOAuthListener(listeners[i]);
            if (listener != null)
                listener.onPersonaAdded(personaIndex);
        }
    }

    private void doBeforeDeletePersona(short personaIndex) {
        for (short i = 0; i < listeners.length; i++) {
            SIOAuthListener listener = getSIOAuthListener(listeners[i]);
            if (listener != null)
                listener.onPersonaDeleted(personaIndex);
        }
    }

    private void doAfterAuthenticatePersona(short personaIndex, short score) {
        for (short i = 0; i < listeners.length; i++) {
            SIOAuthListener listener = getSIOAuthListener(listeners[i]);
            if (listener != null)
                listener.onPersonaAuthenticated(personaIndex, score);
        }
    }

    private void processAddListener() {
        if (!(isCheckC_MAC() && isCheckC_DECRYPTION())) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (!(p1 == P1_ADD_LISTENER && p2 == P2_ADD_LISTENER)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();
        byte[] buffer = getApduData();

        AID listener = JCSystem.lookupAID(buffer, Utils.SHORT_00, (byte) lc);

        if (listener == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short newListenerIndex = addListener(listener);
        short length = Util.setShort(buffer, Utils.SHORT_00, newListenerIndex);
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }
    
    private void processDeleteListener() {
        if (!(isCheckC_MAC() && isCheckC_DECRYPTION())) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (!(p1 == P1_DELETE_LISTENER && p2 == P2_DELETE_LISTENER)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();
        byte[] buffer = getApduData();

        AID listener = JCSystem.lookupAID(buffer, Utils.SHORT_00, (byte) lc);

        if (listener == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        boolean deleted = deleteListener(listener);
        short length = Util.setShort(buffer, Utils.SHORT_00, Util.makeShort(deleted ? (byte) 0x01 : (byte) 0x00, Utils.BYTE_00));
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

    private void processAddPersona() {
        if (!(isCheckC_MAC() || isCheckC_DECRYPTION())) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (!(p1 == P1_ADD_PERSONA && p2 == P2_ADD_PERSONA)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();

        if (lc != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] buffer = getApduData();

        short newPersonaIndex = personasRepository.add();

        doAfterAddPersona(newPersonaIndex);

        short length = Util.setShort(buffer, Utils.SHORT_00, newPersonaIndex);
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

    private void processAddVerifierForPersona() {
        if (!(isCheckC_MAC() && isCheckC_DECRYPTION())) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (!(p1 == P1_ADD_VERIFIER_FOR_PERSONA)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short personaIndex = Util.makeShort(Utils.BYTE_00, p2);

        if (!isPersonaExists(personaIndex)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();
        byte[] buffer = getApduData();

        Verifier verifier = VerifierBuilder.createVerifier(verifierType, buffer, Utils.SHORT_00, lc);

        short newVerifierIndex = personasRepository.getItems()[personaIndex].addVerifier(verifier);
        short length = Util.setShort(buffer, Utils.SHORT_00, newVerifierIndex);
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

    private void processDeletePersona() {
        if (!(isCheckC_MAC() || isCheckC_DECRYPTION())) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (!(p1 == P1_DELETE_PERSONA)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();

        short personaIndex = Util.makeShort(Utils.BYTE_00, p2);

        if (!isPersonaExists(personaIndex)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        doBeforeDeletePersona(personaIndex);
        personasRepository.delete(personaIndex);
    }

    private void processDeleteVerifierFromPersona() {
        if (!(isCheckC_MAC() || isCheckC_DECRYPTION())) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short lc = setIncomingAndReceiveUnwrap();
        short personaIndex = Util.makeShort(Utils.BYTE_00, p1);

        if (!isPersonaExists(personaIndex)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short verifierIndex = Util.makeShort(Utils.BYTE_00, p2);

        if (!personasRepository.getItems()[personaIndex].isVerifierExists(verifierIndex)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        if (!personasRepository.getItems()[personaIndex].deleteVerifierByIndex(verifierIndex)) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
    }

    private void processAuthenticatePersona() {
        if (p1 != P1_UTHENTICATE_PERSONA || p2 != P2_UTHENTICATE_PERSONA) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();

        byte[] buffer = getApduData();

        PersonaAuthenticationResult result = personasRepository.authenticatePersona(buffer, Utils.SHORT_00, lc);

        doAfterAuthenticatePersona(result.personaIndex, result.score);

        short length = 0;
        length = Util.setShort(buffer, length, result.personaIndex);
        length = Util.setShort(buffer, length, result.score);

        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

    private short addListener(AID listener) {
        short newIndex = 0;
        boolean foundNewItem = false;
        for (short i = 0; i < listeners.length; i++) {
            if (listeners[i] == null) {
                newIndex = i;
                foundNewItem = true;
                break;
            } else if (listeners[i].equals(listener)) {
                return i;
            }
        }

        if (!foundNewItem) {
            short extendCount = 1;
            extendListenersArray(extendCount);
            newIndex = (short) (listeners.length - extendCount);
        }

        listeners[newIndex] = listener;
        return newIndex;
    }

    private boolean deleteListener(AID listener) {
        boolean result = false;
        for (short i = 0; i < listeners.length; i++) {
            if (listeners[i] != null && listeners[i].equals(listener)) {
                listeners[i] = null;
                Utils.requestObjectDeletion();
                result = true;
            }
        }
        return result;
    }

    private void extendListenersArray(short extendCount) {
        AID[] arr = new AID[(short) (listeners.length + extendCount)];

        for (short i = 0; i < listeners.length; i++) {
            arr[i] = listeners[i];
        }

        listeners = arr;
        Utils.requestObjectDeletion();
    }

}
