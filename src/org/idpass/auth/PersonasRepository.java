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

final class PersonasRepository {
    
    private Persona[] personas;
    
    
    static PersonasRepository create(short personaInitCount){
        return new PersonasRepository(personaInitCount);
        
    }
    
    private PersonasRepository(short personaInitCount) {
        personas = new Persona[personaInitCount];
    }


    Persona[] getItems() {
        return personas;
    }
    
    boolean isPersonaAuthenticated(short personaIndex) {
        if (!exists(personaIndex))
            return false;

        return personas[personaIndex].isAuthenticated();
    }

    short getPersonasTotalCount() {
        return (short) personas.length;
    }

    boolean exists(short personaIndex) {
        return !(personas.length <= personaIndex || personas[personaIndex] == null);
    }
    
    
    
    PersonaAuthenticationResult authenticatePersona(byte[] buffer, short offset, short length) {
        short personaIndexResult = -1;
        short score = -1;
        for (short i = 0; i < personas.length; i++) {
            if (!exists(i))
                continue;
            score = personas[i].verify(buffer, offset, length);
            if (0 <= score) {
                personaIndexResult = i;
                break;
            }
        }

        return new PersonaAuthenticationResult(personaIndexResult, score);
    }

    short getPersonasCount() {
        short result = 0;

        for (short i = 0; i < personas.length; i++) {
            if (exists(i))
                result++;
        }

        return result;
    }
    
    short add() {
        short newIndex = 0;
        boolean foundNewItem = false;
        for (short i = 0; i < personas.length; i++) {
            if (personas[i] == null) {
                newIndex = i;
                foundNewItem = true;
                break;
            }
        }

        if (!foundNewItem) {
            short extendCount = 1;
            extend(extendCount);
            newIndex = (short) (personas.length - extendCount);
        }

        Persona newPersona = new Persona();
        personas[newIndex] = newPersona;
        return newIndex;
    }
    
    void reset() {
        personas = null;
        Utils.requestObjectDeletion();
    }

    boolean delete(short index) {
        if (personas.length <= index)
            return false;

        if (personas[index] == null) {
            return true;
        }

        personas[index] = null;
        Utils.requestObjectDeletion();
        return true;
    }

    

    private void extend(short extendCount) {
        Persona[] arr = new Persona[(short) (personas.length + extendCount)];

        for (short i = 0; i < personas.length; i++) {
            arr[i] = personas[i];
        }

        personas = arr;
        Utils.requestObjectDeletion();
    }
}
