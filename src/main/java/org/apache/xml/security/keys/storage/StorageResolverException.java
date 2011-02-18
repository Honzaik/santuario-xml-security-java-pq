
/*
 * Copyright  1999-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.xml.security.keys.storage;



import org.apache.xml.security.exceptions.XMLSecurityException;


/**
 *
 * @author $Author$
 */
public class StorageResolverException extends XMLSecurityException {

   /**
         * 
         */
        private static final long serialVersionUID = 1L;

   /**
    * Constructor StorageResolverException
    *
    */
   public StorageResolverException() {
      super();
   }

   /**
    * Constructor StorageResolverException
    *
    * @param msgID
    */
   public StorageResolverException(String msgID) {
      super(msgID);
   }

   /**
    * Constructor StorageResolverException
    *
    * @param msgID
    * @param exArgs
    */
   public StorageResolverException(String msgID, Object exArgs[]) {
      super(msgID, exArgs);
   }

   /**
    * Constructor StorageResolverException
    *
    * @param msgID
    * @param originalException
    */
   public StorageResolverException(String msgID, Exception originalException) {
      super(msgID, originalException);
   }

   /**
    * Constructor StorageResolverException
    *
    * @param msgID
    * @param exArgs
    * @param originalException
    */
   public StorageResolverException(String msgID, Object exArgs[],
                                   Exception originalException) {
      super(msgID, exArgs, originalException);
   }
}
