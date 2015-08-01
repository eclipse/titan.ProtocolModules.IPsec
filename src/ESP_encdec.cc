/******************************************************************************
* Copyright (c) 2005, 2015  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
*
* Contributors:
* Gabor Szalai
* Eszter Susanszky
******************************************************************************/
//
//  File:               ESP_encdec.cc
//  Description:        IPsec ESP
//  Rev:                R2A
//  Prodnr:             CNL 113 809
//  Reference:          http://tools.ietf.org/search/rfc4303
//
///////////////////////////////////////////////////////////////////////////////
#include "ESP_Types.hh"
#include <stdlib.h>

namespace ESP__Types {

  INTEGER ef__ESP__decode(const OCTETSTRING& pl__stream, const INTEGER& pl__auth__length, ESP__Message& pl__pdu)
  {
    if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
      TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
      TTCN_Logger::log_event_str("ef_ESP_decode(): Stream before decoding: ");
      pl__stream.log();
      TTCN_Logger::end_event();
    }
  
    TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_WARNING);
    TTCN_EncDec::clear_error();
  
    TTCN_Buffer ttcn_buffer(pl__stream);
    pl__pdu.decode(ESP__Message_descr_, ttcn_buffer, TTCN_EncDec::CT_RAW);
    
    if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
      if(pl__pdu.encrypted__data().lengthof()>=pl__auth__length){
      pl__pdu.authentication__data() = substr(pl__pdu.encrypted__data(), pl__pdu.encrypted__data().lengthof() - pl__auth__length, pl__auth__length);
      pl__pdu.encrypted__data() = substr(pl__pdu.encrypted__data(), 0, pl__pdu.encrypted__data().lengthof() - pl__auth__length);
      } else {
        TTCN_warning("ef_ESP_decode(): The specified length of the authentication data (%d) is more than the length of the received data(%d)",(int)pl__auth__length,(int)pl__pdu.encrypted__data().lengthof());
        return 1;
      }

    }
    if (TTCN_Logger::log_this_event(TTCN_Logger::DEBUG_ENCDEC)) {
      TTCN_Logger::begin_event(TTCN_Logger::DEBUG_ENCDEC);
      TTCN_Logger::log_event_str("ef_ESP_decode(): Decoded @ESP_Types.ESP_Message: ");
      pl__pdu.log();
      TTCN_Logger::end_event();
    }
  
    if (TTCN_EncDec::get_last_error_type() == TTCN_EncDec::ET_NONE) {
      if (ttcn_buffer.get_pos() < ttcn_buffer.get_len()-1 && TTCN_Logger::log_this_event(TTCN_WARNING)) {
        ttcn_buffer.cut();
        OCTETSTRING remaining_stream;
        ttcn_buffer.get_string(remaining_stream);
        TTCN_Logger::begin_event(TTCN_WARNING);
        TTCN_Logger::log_event_str("ef_ESP_decode(): Warning: Data remained at the end of the stream after successful decoding: ");
        remaining_stream.log();
        TTCN_Logger::end_event();
      }
      return 0;
    }
    
    return 1;
  }
  
}
