/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *          
 */

#include "ns3/test.h"
#include "ns3/core-module.h"
#include "ns3/packet.h"
#include "ns3/log.h"
#include <vector>
#include <stdio.h>
#include <string.h>

#include "ns3/quic-socket-rx-buffer.h"
#include "ns3/quic-stream-rx-buffer.h"
#include "ns3/buffer.h"
#include "ns3/quic-header.h"
#include "ns3/quic-subheader.h"

using namespace ns3;

#define GET_RANDOM_UINT64(RandomVariable) \
  static_cast<uint64_t> (RandomVariable->GetInteger (0, UINT32_MAX << 31))

#define GET_RANDOM_UINT32(RandomVariable) \
  static_cast<uint32_t> (RandomVariable->GetInteger (0, UINT32_MAX))

#define GET_RANDOM_UINT16(RandomVariable) \
  static_cast<uint16_t> (RandomVariable->GetInteger (0, UINT16_MAX))

#define GET_RANDOM_UINT8(RandomVariable) \
  static_cast<uint8_t> (RandomVariable->GetInteger (0, UINT8_MAX))

NS_LOG_COMPONENT_DEFINE("QuicHeaderTestSuite");

/**
 * \ingroup internet-tests
 * \ingroup tests
 *
 * \brief The QuicHeader Test
 */
class QuicHeaderTestCase : public TestCase
{
public:
  QuicHeaderTestCase ();

private:
  virtual void
  DoRun (void);
  virtual void
  DoTeardown (void);

  /**
   * \brief Check the correct header serialization/deserialization.
   */
  void
  TestQuicHeaderSerializeDeserialize ();

};

/**
 * \ingroup internet-tests
 * \ingroup tests
 *
 * \brief The QuicSubHeader Test
 */
class QuicSubHeaderTestCase : public TestCase
{
public:
  QuicSubHeaderTestCase ();

private:
  virtual void
  DoRun (void);
  virtual void
  DoTeardown (void);

  /**
   * \brief Check the correct subheader serialization/deserialization.
   */
  void
  TestQuicSubHeaderSerializeDeserialize ();

};


QuicHeaderTestCase::QuicHeaderTestCase () :
    TestCase ("QuicHeader Test")
{
}

void
QuicHeaderTestCase::DoRun ()
{
  TestQuicHeaderSerializeDeserialize ();
}

QuicSubHeaderTestCase::QuicSubHeaderTestCase () :
    TestCase ("QuicSubHeader Test")
{
}

void
QuicSubHeaderTestCase::DoRun ()
{
  TestQuicSubHeaderSerializeDeserialize ();
}


void
QuicHeaderTestCase::TestQuicHeaderSerializeDeserialize ()
{
  Buffer buffer;
  QuicHeader head;
  QuicHeader copyHead;

  Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable> ();
  for (uint32_t i = 0; i < 1000; ++i)
    {
      uint64_t connectionId = GET_RANDOM_UINT64 (x);
      uint32_t version = GET_RANDOM_UINT32 (x);
      SequenceNumber32 packetNumber = SequenceNumber32(GET_RANDOM_UINT32 (x));
      std::vector<uint32_t> supportedVersions;

      for ( int h_case = QuicHeader::VERSION_NEGOTIATION; 
        h_case != QuicHeader::NONE; h_case++ )
        {
          switch ( h_case )
          {
              case QuicHeader::VERSION_NEGOTIATION: // TODO: Update when full supported
                  head = QuicHeader::CreateVersionNegotiation (connectionId, version, supportedVersions);

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::VERSION_NEGOTIATION,
                                             "Different type byte found");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, head.GetConnectionId (),
                                             "Different connection id found");
                  NS_TEST_ASSERT_MSG_EQ (version, head.GetVersion (),
                                             "Different version found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::VERSION_NEGOTIATION,
                                         "Different type byte found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, copyHead.GetConnectionId (),
                                             "Different connection id found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (version, copyHead.GetVersion (),
                                             "Different version found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word in deserialized header"); 
                  break;
              case QuicHeader::INITIAL:
                  head = QuicHeader::CreateInitial (connectionId, version, packetNumber);

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::INITIAL,
                                             "Different type byte found");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, head.GetConnectionId (),
                                             "Different connection id found");
                  NS_TEST_ASSERT_MSG_EQ (version, head.GetVersion (),
                                             "Different version found");
                  NS_TEST_ASSERT_MSG_EQ (packetNumber, head.GetPacketNumber (),
                                             "Different packet number found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::INITIAL,
                                         "Different type byte found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, copyHead.GetConnectionId (),
                                             "Different connection id found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (version, copyHead.GetVersion (),
                                             "Different version found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (packetNumber, copyHead.GetPacketNumber (),
                                             "Different packet number found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word in deserialized header"); 
                  break;
              case QuicHeader::RETRY:
                  head = QuicHeader::CreateRetry (connectionId, version, packetNumber);

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::RETRY,
                                             "Different type byte found");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, head.GetConnectionId (),
                                             "Different connection id found");
                  NS_TEST_ASSERT_MSG_EQ (version, head.GetVersion (),
                                             "Different version found");
                  NS_TEST_ASSERT_MSG_EQ (packetNumber, head.GetPacketNumber (),
                                             "Different packet number found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::RETRY,
                                         "Different type byte found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, copyHead.GetConnectionId (),
                                             "Different connection id found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (version, copyHead.GetVersion (),
                                             "Different version found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (packetNumber, copyHead.GetPacketNumber (),
                                             "Different packet number found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word in deserialized header"); 
                  break;
              case QuicHeader::HANDSHAKE:
                  head = QuicHeader::CreateHandshake (connectionId, version, packetNumber);

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::HANDSHAKE,
                                             "Different type byte found");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, head.GetConnectionId (),
                                             "Different connection id found");
                  NS_TEST_ASSERT_MSG_EQ (version, head.GetVersion (),
                                             "Different version found");
                  NS_TEST_ASSERT_MSG_EQ (packetNumber, head.GetPacketNumber (),
                                             "Different packet number found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::HANDSHAKE,
                                         "Different type byte found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, copyHead.GetConnectionId (),
                                             "Different connection id found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (version, copyHead.GetVersion (),
                                             "Different version found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (packetNumber, copyHead.GetPacketNumber (),
                                             "Different packet number found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word in deserialized header"); 
                  break;
              case QuicHeader::ZRTT_PROTECTED:
                  head = QuicHeader::Create0RTT (connectionId, version, packetNumber);

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::ZRTT_PROTECTED,
                                             "Different type byte found");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, head.GetConnectionId (),
                                             "Different connection id found");
                  NS_TEST_ASSERT_MSG_EQ (version, head.GetVersion (),
                                             "Different version found");
                  NS_TEST_ASSERT_MSG_EQ (packetNumber, head.GetPacketNumber (),
                                             "Different packet number found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::LONG,
                                             "Different format found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (head.GetTypeByte (), QuicHeader::ZRTT_PROTECTED,
                                         "Different type byte found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (connectionId, copyHead.GetConnectionId (),
                                             "Different connection id found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (version, copyHead.GetVersion (),
                                             "Different version found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (packetNumber, copyHead.GetPacketNumber (),
                                             "Different packet number found in deserialized header");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), 17, 
                    "QuicHeader for Long Packet is not 17 word in deserialized header"); 
                  break;
               default:
                  break;
          }
        }
        
        bool connectionIdFlag = (i % 2 == 0) ? true : false;
        bool keyPhaseBit = (i % 2 == 0) ? QuicHeader::PHASE_ZERO : QuicHeader::PHASE_ONE;

        head = QuicHeader::CreateShort (connectionId, packetNumber, connectionIdFlag, keyPhaseBit);

        NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 1 + 8*connectionIdFlag + head.GetPacketNumLen ()/8, 
          "QuicHeader for Short Packet is not as expected");

        buffer.AddAtStart (head.GetSerializedSize ());
        head.Serialize (buffer.Begin ());

        NS_TEST_ASSERT_MSG_EQ (head.GetFormat (), QuicHeader::SHORT,
                                   "Different format found");
        NS_TEST_ASSERT_MSG_EQ (head.GetKeyPhaseBit (), keyPhaseBit,
                                   "Different key phase bit found");
        NS_TEST_ASSERT_MSG_EQ (packetNumber, head.GetPacketNumber (),
                                   "Different packet number found");        
        if (connectionIdFlag) {
          NS_TEST_ASSERT_MSG_EQ (connectionId, head.GetConnectionId (),
                                             "Different connection id found");
        }
        NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), 1 + 8*connectionIdFlag + head.GetPacketNumLen ()/8, 
          "QuicHeader for Short Packet is not as expected");

        copyHead.Deserialize (buffer.Begin ());

        NS_TEST_ASSERT_MSG_EQ (copyHead.GetFormat (), QuicHeader::SHORT,
                                   "Different format found");
        NS_TEST_ASSERT_MSG_EQ (copyHead.GetKeyPhaseBit (), keyPhaseBit,
                                   "Different key phase bit found");
        NS_TEST_ASSERT_MSG_EQ (packetNumber, copyHead.GetPacketNumber (),
                                   "Different packet number found");        
        if (connectionIdFlag) {
          NS_TEST_ASSERT_MSG_EQ (connectionId, copyHead.GetConnectionId (),
                                             "Different connection id found");
        }
        NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), 1 + 8*connectionIdFlag + copyHead.GetPacketNumLen ()/8, 
          "QuicHeader for Short Packet is not as expected");
    } 
}

void
QuicSubHeaderTestCase::TestQuicSubHeaderSerializeDeserialize ()
{
  Buffer buffer;
  QuicSubheader head;
  QuicSubheader copyHead;

  Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable> ();
  for (uint32_t i = 0; i < 1000; ++i)
    {
      uint32_t headSize = 0;
      uint64_t streamId = GET_RANDOM_UINT64 (x);
      uint16_t applicationErrorCode = GET_RANDOM_UINT16 (x);
      uint64_t finalOffset = GET_RANDOM_UINT64 (x);
      uint16_t errorCode = GET_RANDOM_UINT16 (x);
      const char* reasonPhrase = "test";
      uint64_t maxData = GET_RANDOM_UINT64 (x);
      uint64_t maxStreamData = GET_RANDOM_UINT64 (x);
      uint64_t maxStreamId = GET_RANDOM_UINT64 (x);
      uint64_t offset = GET_RANDOM_UINT64 (x);
      uint64_t sequence = GET_RANDOM_UINT64 (x);
      uint64_t connectionId = GET_RANDOM_UINT64 (x);
      uint32_t largestAcknowledged = GET_RANDOM_UINT32 (x);
      uint64_t ackDelay = GET_RANDOM_UINT64 (x);
      uint32_t firstAckBlock = GET_RANDOM_UINT32 (x);
      std::vector<uint32_t> gaps(10, 1);
      std::vector<uint32_t> additionalAckBlocks(10, 1);
      uint8_t data = GET_RANDOM_UINT8 (x);
      uint64_t length = GET_RANDOM_UINT64 (x);

      for ( int h_case = QuicSubheader::PADDING; 
        h_case != QuicSubheader::STREAM111 +1; h_case++ )
        {
          switch ( h_case )
          {
              case QuicSubheader::PADDING:
                  head = QuicSubheader::CreatePadding ();

                  headSize = 1;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PADDING frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::PADDING,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PADDING frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::PADDING,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PADDING frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::RST_STREAM:
                  head = QuicSubheader::CreateRstStream (streamId, applicationErrorCode, finalOffset);

                  headSize = 3 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(finalOffset)/8;
                  
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for RST_STREAM frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::RST_STREAM,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetErrorCode (), applicationErrorCode,
                                             "Different application error code id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetOffset (), finalOffset,
                                             "Different final offset found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for RST_STREAM frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::RST_STREAM,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetErrorCode (), applicationErrorCode,
                                             "Different application error code id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetOffset (), finalOffset,
                                             "Different final offset found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for RST_STREAM frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::CONNECTION_CLOSE:
                  head = QuicSubheader::CreateConnectionClose (errorCode, reasonPhrase);

                  headSize = 3 + QuicSubheader::GetVarInt64Size(strlen(reasonPhrase))/8 + strlen(reasonPhrase);

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for CONNECTION_CLOSE frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::CONNECTION_CLOSE,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetErrorCode (), errorCode,
                                             "Different error code id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetReasonPhraseLength (), strlen(reasonPhrase),
                                             "Different reason phrase lenght found");
                  for (uint64_t j = 0; j < strlen(reasonPhrase); j++)
                    {
                      NS_TEST_ASSERT_MSG_EQ (head.GetReasonPhrase ()[j], reasonPhrase[j],
                                               "Different reason phrase found");
                    }
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for CONNECTION_CLOSE frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::CONNECTION_CLOSE,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetErrorCode (), errorCode,
                                             "Different error code id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetReasonPhraseLength (), strlen(reasonPhrase),
                                             "Different reason phrase lenght found in deserialized subheader");
                  for (uint64_t j = 0; j < strlen(reasonPhrase); j++)
                    {
                      NS_TEST_ASSERT_MSG_EQ (copyHead.GetReasonPhrase ()[j], reasonPhrase[j],
                                               "Different reason phrase found");
                    }
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for CONNECTION_CLOSE frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::APPLICATION_CLOSE:
                  head = QuicSubheader::CreateApplicationClose (errorCode, reasonPhrase);

                  headSize = 3 + QuicSubheader::GetVarInt64Size(strlen(reasonPhrase))/8 + strlen(reasonPhrase);

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for APPLICATION_CLOSE frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::APPLICATION_CLOSE,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetErrorCode (), errorCode,
                                             "Different error code id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetReasonPhraseLength (), strlen(reasonPhrase),
                                             "Different reason phrase lenght found");
                  for (uint64_t j = 0; j < strlen(reasonPhrase); j++)
                    {
                      NS_TEST_ASSERT_MSG_EQ (head.GetReasonPhrase ()[j], reasonPhrase[j],
                                               "Different reason phrase found");
                    }
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for APPLICATION_CLOSE frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::APPLICATION_CLOSE,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetErrorCode (), errorCode,
                                             "Different error code id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetReasonPhraseLength (), strlen(reasonPhrase),
                                             "Different reason phrase lenght found in deserialized subheader");
                  for (uint64_t j = 0; j < strlen(reasonPhrase); j++)
                    {
                      NS_TEST_ASSERT_MSG_EQ (copyHead.GetReasonPhrase ()[j], reasonPhrase[j],
                                               "Different reason phrase found");
                    }
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for APPLICATION_CLOSE frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::MAX_DATA:
                  head = QuicSubheader::CreateMaxData (maxData);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(maxData)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_DATA frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::MAX_DATA,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetMaxData (), maxData,
                                             "Different max data found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_DATA frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::MAX_DATA,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetMaxData (), maxData,
                                             "Different max data found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_DATA frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::MAX_STREAM_DATA:
                  head = QuicSubheader::CreateMaxStreamData (streamId, maxStreamData);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(maxStreamData)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_STREAM_DATA frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::MAX_STREAM_DATA,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetMaxStreamData (), maxStreamData,
                                             "Different max stream data found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_STREAM_DATA frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::MAX_STREAM_DATA,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetMaxStreamData (), maxStreamData,
                                             "Different max stream data found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_STREAM_DATA frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::MAX_STREAM_ID:
                  head = QuicSubheader::CreateMaxStreamId (maxStreamId);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(maxStreamId)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_STREAM_ID frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::MAX_STREAM_ID,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetMaxStreamId (), maxStreamId,
                                             "Different max stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_STREAM_ID frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::MAX_STREAM_ID,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetMaxStreamId (), maxStreamId,
                                             "Different max stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for MAX_STREAM_ID frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::PING:
                  head = QuicSubheader::CreatePing ();

                  headSize = 1;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PING frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::PING,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PING frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::PING,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PING frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::BLOCKED:
                  head = QuicSubheader::CreateBlocked (offset);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(offset)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for BLOCKED frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::BLOCKED,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetOffset (), offset,
                                             "Different offset found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for BLOCKED frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::BLOCKED,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetOffset (), offset,
                                             "Different offset found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for BLOCKED frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM_BLOCKED:
                  head = QuicSubheader::CreateStreamBlocked (streamId, offset);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(offset)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM_BLOCKED frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM_BLOCKED,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetOffset (), offset,
                                             "Different offset found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM_BLOCKED frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM_BLOCKED,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetOffset (), offset,
                                             "Different offset found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM_BLOCKED frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM_ID_BLOCKED:
                  head = QuicSubheader::CreateStreamIdBlocked (streamId);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM_ID_BLOCKED frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM_ID_BLOCKED,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM_ID_BLOCKED frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM_ID_BLOCKED,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM_ID_BLOCKED frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::NEW_CONNECTION_ID:
                  head = QuicSubheader::CreateNewConnectionId (sequence, connectionId);

                  headSize = 9 + QuicSubheader::GetVarInt64Size(sequence)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for NEW_CONNECTION_ID frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::NEW_CONNECTION_ID,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetConnectionId (), connectionId,
                                             "Different connection id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSequence (), sequence,
                                             "Different sequence found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for NEW_CONNECTION_ID frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::NEW_CONNECTION_ID,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetConnectionId (), connectionId,
                                             "Different connection id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSequence (), sequence,
                                             "Different sequence found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for NEW_CONNECTION_ID frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STOP_SENDING:
                  head = QuicSubheader::CreateStopSending (streamId, applicationErrorCode);

                  headSize = 3 + QuicSubheader::GetVarInt64Size(streamId)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STOP_SENDING frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STOP_SENDING,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetErrorCode (), applicationErrorCode,
                                             "Different application error code found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STOP_SENDING frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STOP_SENDING,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetErrorCode (), applicationErrorCode,
                                             "Different application error code found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STOP_SENDING frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::ACK:
                  head = QuicSubheader::CreateAck (largestAcknowledged, ackDelay, firstAckBlock, gaps, additionalAckBlocks);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(largestAcknowledged)/8 + 
                    QuicSubheader::GetVarInt64Size(ackDelay)/8 + QuicSubheader::GetVarInt64Size(gaps.size ())/8 +
                    QuicSubheader::GetVarInt64Size(firstAckBlock)/8;
                  for (uint64_t j = 0; j < gaps.size (); j++)
                    {
                      headSize += QuicSubheader::GetVarInt64Size (gaps[j])/8;
                      headSize += QuicSubheader::GetVarInt64Size (additionalAckBlocks[j])/8;
                    }

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for ACK frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::ACK,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetLargestAcknowledged (), largestAcknowledged,
                                             "Different largest acknowledged found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetAckDelay (), ackDelay,
                                             "Different ack delay found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetAckBlockCount (), gaps.size (),
                                             "Different ack block count found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetFirstAckBlock (), firstAckBlock,
                                             "Different first ack block found");
                  for (uint64_t j = 0; j < gaps.size (); j++)
                    {
                      NS_TEST_ASSERT_MSG_EQ (head.GetGaps ()[j], gaps[j],
                                               "Different gap found");
                      NS_TEST_ASSERT_MSG_EQ (head.GetAdditionalAckBlocks ()[j], additionalAckBlocks[j],
                                               "Different additional ack block found");
                    }
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for ACK frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::ACK,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetLargestAcknowledged (), largestAcknowledged,
                                             "Different largest acknowledged found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetAckDelay (), ackDelay,
                                             "Different ack delay found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetAckBlockCount (), gaps.size (),
                                             "Different ack block count found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFirstAckBlock (), firstAckBlock,
                                             "Different first ack block found in deserialized subheader");

                  for (uint64_t j = 0; j < gaps.size (); j++)
                    {
                      NS_TEST_ASSERT_MSG_EQ (copyHead.GetGaps ()[j], gaps[j],
                                               "Different gap found in deserialized subheader");
                      NS_TEST_ASSERT_MSG_EQ (copyHead.GetAdditionalAckBlocks ()[j], additionalAckBlocks[j],
                                               "Different additional ack block found in deserialized subheader");
                    }
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for ACK frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::PATH_CHALLENGE:
                  head = QuicSubheader::CreatePathChallenge (data);

                  headSize = 2;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PATH_CHALLENGE frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::PATH_CHALLENGE,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetData (), data,
                                             "Different data found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PATH_CHALLENGE frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::PATH_CHALLENGE,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetData (), data,
                                             "Different data found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PATH_CHALLENGE frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::PATH_RESPONSE:
                  head = QuicSubheader::CreatePathResponse (data);

                  headSize = 2;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PATH_RESPONSE frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::PATH_RESPONSE,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetData (), data,
                                             "Different data found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PATH_RESPONSE frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::PATH_RESPONSE,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetData (), data,
                                             "Different data found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for PATH_RESPONSE frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM000:
                  head = QuicSubheader::CreateStreamSubHeader (streamId, offset, length, 
                    false, false, false);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM000 frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM000,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM000 frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM000,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM000 frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM001:
                  head = QuicSubheader::CreateStreamSubHeader (streamId, offset, length, 
                    false, false, true);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM001 frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM001,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM001 frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM001,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM001 frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM010:
                  head = QuicSubheader::CreateStreamSubHeader (streamId, offset, length, 
                    false, true, false);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(length)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM010 frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM010,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetLength (), length,
                                             "Different length found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM010 frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM010,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetLength (), length,
                                             "Different length found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM010 frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM011:
                  head = QuicSubheader::CreateStreamSubHeader (streamId, offset, length, 
                    false, true, true);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(length)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM011 frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM011,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetLength (), length,
                                             "Different length found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM011 frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM011,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetLength (), length,
                                             "Different length found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM011 frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM100:
                  head = QuicSubheader::CreateStreamSubHeader (streamId, offset, length, 
                    true, false, false);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(offset)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM100 frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM100,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetOffset (), offset,
                                             "Different offset found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM100 frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM100,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetOffset (), offset,
                                             "Different offset in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM100 frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM101:
                  head = QuicSubheader::CreateStreamSubHeader (streamId, offset, length, 
                    true, false, true);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(offset)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM101 frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM101,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetOffset (), offset,
                                             "Different offset found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM101 frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM101,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetOffset (), offset,
                                             "Different offset in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM101 frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM110:
                  head = QuicSubheader::CreateStreamSubHeader (streamId, offset, length, 
                    true, true, false);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(offset)/8 + QuicSubheader::GetVarInt64Size(length)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM110 frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM110,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetOffset (), offset,
                                             "Different offset found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetLength (), length,
                                             "Different length found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM110 frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM110,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetOffset (), offset,
                                             "Different offset in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetLength (), length,
                                             "Different length found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM110 frame is not as expected in deserialized subheader");
                  break;
              case QuicSubheader::STREAM111:
                  head = QuicSubheader::CreateStreamSubHeader (streamId, offset, length, 
                    true, true, true);

                  headSize = 1 + QuicSubheader::GetVarInt64Size(streamId)/8 + QuicSubheader::GetVarInt64Size(offset)/8 + QuicSubheader::GetVarInt64Size(length)/8;

                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM111 frame is not as expected");

                  buffer.AddAtStart (head.GetSerializedSize ());
                  head.Serialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (head.GetFrameType (), QuicSubheader::STREAM111,
                                             "Different frame type found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetStreamId (), streamId,
                                             "Different stream id found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetOffset (), offset,
                                             "Different offset found");
                  NS_TEST_ASSERT_MSG_EQ (head.GetLength (), length,
                                             "Different length found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (head.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM111 frame is not as expected");

                  copyHead.Deserialize (buffer.Begin ());

                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetFrameType (), QuicSubheader::STREAM111,
                                             "Different frame type found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetStreamId (), streamId,
                                             "Different stream id found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetOffset (), offset,
                                             "Different offset in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetLength (), length,
                                             "Different length found in deserialized subheader");
                  NS_TEST_ASSERT_MSG_EQ (copyHead.GetSerializedSize (), headSize, 
                    "QuicSubHeader for STREAM111 frame is not as expected in deserialized subheader");
                  break;
               default:
                  break;
          }
        }
      
    } 
}



void
QuicHeaderTestCase::DoTeardown ()
{
}

void
QuicSubHeaderTestCase::DoTeardown ()
{
}

/**
 * \ingroup internet-test
 * \ingroup tests
 *
 * \brief the TestSuite for the QuicHeader test cases
 */
class QuicHeaderTestSuite : public TestSuite
{
public:
  QuicHeaderTestSuite () :
      TestSuite ("quic-header", UNIT)
  {
    AddTestCase (new QuicHeaderTestCase, TestCase::QUICK);
    AddTestCase (new QuicSubHeaderTestCase, TestCase::QUICK);
  }
};
static QuicHeaderTestSuite g_QuicHeaderTestSuite;
