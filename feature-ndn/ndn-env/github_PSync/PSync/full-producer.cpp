/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2022,  The University of Memphis
 *
 * This file is part of PSync.
 * See AUTHORS.md for complete list of PSync authors and contributors.
 *
 * PSync is free software: you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * PSync is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * PSync, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "PSync/full-producer.hpp"
#include "PSync/detail/state.hpp"
#include "PSync/detail/util.hpp"

#include <ndn-cxx/security/validator-null.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/segment-fetcher.hpp>

#include <cstring>

namespace psync {

NDN_LOG_INIT(psync.FullProducer);

FullProducer::FullProducer(const size_t expectedNumEntries,
                           ndn::Face& face,
                           const ndn::Name& syncPrefix,
                           const ndn::Name& userPrefix,
                           const UpdateCallback& onUpdateCallBack,
                           ndn::time::milliseconds syncInterestLifetime,
                           ndn::time::milliseconds syncReplyFreshness,
                           CompressionScheme ibltCompression,
                           CompressionScheme contentCompression)
  : ProducerBase(expectedNumEntries, face, syncPrefix, userPrefix, syncReplyFreshness,
                 ibltCompression, contentCompression)
  , m_syncInterestLifetime(syncInterestLifetime)
  , m_onUpdate(onUpdateCallBack)
  , m_jitter(100, 500)
{
  m_registeredPrefix = m_face.setInterestFilter(
                         ndn::InterestFilter(m_syncPrefix).allowLoopback(false),
                         std::bind(&FullProducer::onSyncInterest, this, _1, _2),
                         std::bind(&FullProducer::onRegisterFailed, this, _1, _2));

  // Should we do this after setInterestFilter success call back
  // (Currently following ChronoSync's way)
  sendSyncInterest();
}

FullProducer::~FullProducer()
{
  if (m_fetcher) {
    m_fetcher->stop();
  }
}

void
FullProducer::publishName(const ndn::Name& prefix, ndn::optional<uint64_t> seq)
{
  if (m_prefixes.find(prefix) == m_prefixes.end()) {
    NDN_LOG_WARN("Prefix not added: " << prefix);
    return;
  }

  uint64_t newSeq = seq.value_or(m_prefixes[prefix] + 1);

  NDN_LOG_INFO("Publish: " << prefix << "/" << newSeq);

  updateSeqNo(prefix, newSeq);

  satisfyPendingInterests();
}

void
FullProducer::sendSyncInterest()
{
  // If we send two sync interest one after the other
  // since there is no new data in the network yet,
  // when data is available it may satisfy both of them
  if (m_fetcher) {
    m_fetcher->stop();
  }

  // Sync Interest format for full sync: /<sync-prefix>/<ourLatestIBF>
  ndn::Name syncInterestName = m_syncPrefix;

  // Append our latest IBF
  m_iblt.appendToName(syncInterestName);

  m_outstandingInterestName = syncInterestName;

  m_scheduledSyncInterestId =
    m_scheduler.schedule(m_syncInterestLifetime / 2 + ndn::time::milliseconds(m_jitter(m_rng)),
                         [this] { sendSyncInterest(); });

  ndn::Interest syncInterest(syncInterestName);

  using ndn::util::SegmentFetcher;
  SegmentFetcher::Options options;
  options.interestLifetime = m_syncInterestLifetime;
  options.maxTimeout = m_syncInterestLifetime;
  options.rttOptions.initialRto = m_syncInterestLifetime;

  m_fetcher = SegmentFetcher::start(m_face, syncInterest,
                                    ndn::security::getAcceptAllValidator(), options);

  m_fetcher->onComplete.connect([this, syncInterest] (const ndn::ConstBufferPtr& bufferPtr) {
    onSyncData(syncInterest, bufferPtr);
  });

  m_fetcher->onError.connect([this] (uint32_t errorCode, const std::string& msg) {
    NDN_LOG_ERROR("Cannot fetch sync data, error: " << errorCode << ", message: " << msg);
    // We would like to recover from errors like NoRoute NACK quicker than sync Interest timeout.
    // We don't react to Interest timeout here as we have scheduled the next sync Interest
    // to be sent in half the sync Interest lifetime + jitter above. So we would react to
    // timeout before it happens.
    if (errorCode != SegmentFetcher::ErrorCode::INTEREST_TIMEOUT) {
      auto after = ndn::time::milliseconds(m_jitter(m_rng));
      NDN_LOG_DEBUG("Schedule sync interest after: " << after);
      m_scheduledSyncInterestId = m_scheduler.schedule(after, [this] { sendSyncInterest(); });
    }
  });

  NDN_LOG_DEBUG("sendFullSyncInterest, nonce: " << syncInterest.getNonce() <<
                ", hash: " << std::hash<ndn::Name>{}(syncInterestName));
}

void
FullProducer::onSyncInterest(const ndn::Name& prefixName, const ndn::Interest& interest)
{
  // TODO: answer only segments from store.
  if (m_segmentPublisher.replyFromStore(interest.getName())) {
    return;
  }

  ndn::Name nameWithoutSyncPrefix = interest.getName().getSubName(prefixName.size());
  ndn::Name interestName;

  if (nameWithoutSyncPrefix.size() == 1) {
    // Get /<prefix>/IBF from /<prefix>/IBF
    interestName = interest.getName();
  }
  else if (nameWithoutSyncPrefix.size() == 3) {
    // Get /<prefix>/IBF from /<prefix>/IBF/<version>/<segment-no>
    interestName = interest.getName().getPrefix(-2);
  }
  else {
    return;
  }

  ndn::name::Component ibltName = interestName.get(interestName.size() - 1);

  NDN_LOG_DEBUG("Full sync Interest received, nonce: " << interest.getNonce() <<
                ", hash: " << std::hash<ndn::Name>{}(interestName));

  detail::IBLT iblt(m_expectedNumEntries, m_ibltCompression);
  try {
    iblt.initialize(ibltName);
  }
  catch (const std::exception& e) {
    NDN_LOG_WARN(e.what());
    return;
  }

  auto diff = m_iblt - iblt;

  std::set<uint32_t> positive;
  std::set<uint32_t> negative;

  if (!diff.listEntries(positive, negative)) {
    NDN_LOG_TRACE("Cannot decode differences, positive: " << positive.size()
                  << " negative: " << negative.size() << " m_threshold: "
                  << m_threshold);

    // Send all data if greater then threshold, else send positive below as usual
    // Or send if we can't get neither positive nor negative differences
    if (positive.size() + negative.size() >= m_threshold ||
        (positive.size() == 0 && negative.size() == 0)) {
      detail::State state;
      for (const auto& content : m_prefixes) {
        if (content.second != 0) {
          state.addContent(ndn::Name(content.first).appendNumber(content.second));
        }
      }

      if (!state.getContent().empty()) {
        sendSyncData(interest.getName(), state.wireEncode());
      }

      return;
    }
  }

  detail::State state;
  for (const auto& hash : positive) {
    auto nameIt = m_biMap.left.find(hash);
    if (nameIt != m_biMap.left.end()) {
      ndn::Name nameWithoutSeq = nameIt->second.getPrefix(-1);
      // Don't sync up sequence number zero
      if (m_prefixes[nameWithoutSeq] != 0 &&
          !isFutureHash(nameWithoutSeq, negative)) {
        state.addContent(nameIt->second);
      }
    }
  }

  if (!state.getContent().empty()) {
    NDN_LOG_DEBUG("Sending sync content: " << state);
    sendSyncData(interestName, state.wireEncode());
    return;
  }

  auto& entry = m_pendingEntries.emplace(interestName, PendingEntryInfo{iblt, {}}).first->second;
  entry.expirationEvent = m_scheduler.schedule(interest.getInterestLifetime(),
                          [this, interest] {
                            NDN_LOG_TRACE("Erase pending Interest " << interest.getNonce());
                            m_pendingEntries.erase(interest.getName());
                          });
}

void
FullProducer::sendSyncData(const ndn::Name& name, const ndn::Block& block)
{
  NDN_LOG_DEBUG("Checking if data will satisfy our own pending interest");

  ndn::Name nameWithIblt;
  m_iblt.appendToName(nameWithIblt);

  // TODO: Remove appending of hash - serves no purpose to the receiver
  ndn::Name dataName(ndn::Name(name).appendNumber(std::hash<ndn::Name>{}(nameWithIblt)));

  auto content = detail::compress(m_contentCompression, block.wire(), block.size());

  // checking if our own interest got satisfied
  if (m_outstandingInterestName == name) {
    NDN_LOG_DEBUG("Satisfied our own pending interest");
    // remove outstanding interest
    if (m_fetcher) {
      NDN_LOG_DEBUG("Removing our pending interest from face (stop fetcher)");
      m_fetcher->stop();
      m_outstandingInterestName = ndn::Name("");
    }

    NDN_LOG_DEBUG("Sending sync Data");

    // Send data after removing pending sync interest on face
    m_segmentPublisher.publish(name, dataName, content, m_syncReplyFreshness);

    NDN_LOG_TRACE("Renewing sync interest");
    sendSyncInterest();
  }
  else {
    NDN_LOG_DEBUG("Sending sync Data");
    m_segmentPublisher.publish(name, dataName, content, m_syncReplyFreshness);
  }
}

void
FullProducer::onSyncData(const ndn::Interest& interest, const ndn::ConstBufferPtr& bufferPtr)
{
  deletePendingInterests(interest.getName());

  detail::State state;
  try {
    auto decompressed = detail::decompress(m_contentCompression, bufferPtr->data(), bufferPtr->size());
    state.wireDecode(ndn::Block(std::move(decompressed)));
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot parse received sync Data: " << e.what());
    return;
  }

  NDN_LOG_DEBUG("Sync Data received: " << state);

  std::vector<MissingDataInfo> updates;

  for (const auto& content : state) {
    ndn::Name prefix = content.getPrefix(-1);
    uint64_t seq = content.get(content.size() - 1).toNumber();

    if (m_prefixes.find(prefix) == m_prefixes.end() || m_prefixes[prefix] < seq) {
      updates.push_back({prefix, m_prefixes[prefix] + 1, seq});
      updateSeqNo(prefix, seq);
      // We should not call satisfyPendingSyncInterests here because we just
      // got data and deleted pending interest by calling deletePendingFullSyncInterests
      // But we might have interests not matching to this interest that might not have deleted
      // from pending sync interest
    }
  }

  // We just got the data, so send a new sync interest
  if (!updates.empty()) {
    m_onUpdate(updates);
    NDN_LOG_TRACE("Renewing sync interest");
    sendSyncInterest();
  }
  else {
    NDN_LOG_TRACE("No new update, interest nonce: " << interest.getNonce() <<
                  " , hash: " << std::hash<ndn::Name>{}(interest.getName()));
  }
}

void
FullProducer::satisfyPendingInterests()
{
  NDN_LOG_DEBUG("Satisfying full sync interest: " << m_pendingEntries.size());

  for (auto it = m_pendingEntries.begin(); it != m_pendingEntries.end();) {
    const auto& entry = it->second;
    auto diff = m_iblt - entry.iblt;
    std::set<uint32_t> positive;
    std::set<uint32_t> negative;

    if (!diff.listEntries(positive, negative)) {
      NDN_LOG_TRACE("Decode failed for pending interest");
      if (positive.size() + negative.size() >= m_threshold ||
          (positive.size() == 0 && negative.size() == 0)) {
        NDN_LOG_TRACE("pos + neg > threshold or no diff can be found, erase pending interest");
        it = m_pendingEntries.erase(it);
        continue;
      }
    }

    detail::State state;
    for (const auto& hash : positive) {
      auto nameIt = m_biMap.left.find(hash);
      if (nameIt != m_biMap.left.end()) {
        if (m_prefixes[nameIt->second.getPrefix(-1)] != 0) {
          state.addContent(nameIt->second);
        }
      }
    }

    if (!state.getContent().empty()) {
      NDN_LOG_DEBUG("Satisfying sync content: " << state);
      sendSyncData(it->first, state.wireEncode());
      it = m_pendingEntries.erase(it);
    }
    else {
      ++it;
    }
  }
}

bool
FullProducer::isFutureHash(const ndn::Name& prefix, const std::set<uint32_t>& negative)
{
  auto nextHash = detail::murmurHash3(detail::N_HASHCHECK,
                                      ndn::Name(prefix).appendNumber(m_prefixes[prefix] + 1));
  return negative.find(nextHash) != negative.end();
}

void
FullProducer::deletePendingInterests(const ndn::Name& interestName)
{
  auto it = m_pendingEntries.find(interestName);
  if (it != m_pendingEntries.end()) {
    NDN_LOG_TRACE("Delete pending interest: " << interestName);
    it = m_pendingEntries.erase(it);
  }
}

} // namespace psync
