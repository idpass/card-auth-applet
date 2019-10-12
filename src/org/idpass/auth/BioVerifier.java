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

import javacardx.biometry.BioBuilder;
import javacardx.biometry.BioTemplate;
import javacardx.biometry.OwnerBioTemplate;

/**
 * Bio authentication Verifier implementation
 *
 */
final class BioVerifier implements Verifier {
    private OwnerBioTemplate  template;
    private byte              tryLimit;

    BioVerifier(byte bioType, byte tryLimit, byte[] buffer, short offset, short length) {
        this.tryLimit = tryLimit;
        template = BioBuilder.buildBioTemplate(bioType, tryLimit);
        template.init(buffer, offset, length);
        template.doFinal();
    }

    public VerificationResult verify(byte[] buffer, short offset, short length) {
        short score = template.initMatch(buffer, offset, length);

        if (template.getTriesRemaining() == 0) {
            template.resetUnblockAndSetTryLimit(tryLimit);
        }

        return new VerificationResult(score, BioTemplate.MINIMUM_SUCCESSFUL_MATCH_SCORE <= score);
    }
}
