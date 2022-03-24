/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2020,  Regents of the University of California.
 *
 * This file is part of ndn-tools (Named Data Networking Essential Tools).
 * See AUTHORS.md for complete list of ndn-tools authors and contributors.
 *
 * ndn-tools is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-tools is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-tools, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NDN_TOOLS_TESTS_KEY_CHAIN_FIXTURE_HPP
#define NDN_TOOLS_TESTS_KEY_CHAIN_FIXTURE_HPP

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace tests {

/**
 * @brief A fixture providing an in-memory KeyChain.
 *
 * Test cases can use this fixture to create identities. Identities, certificates, and
 * saved certificates are automatically removed during test teardown.
 */
class KeyChainFixture
{
protected:
  using Certificate = ndn::security::Certificate;
  using Identity    = ndn::security::Identity;
  using Key         = ndn::security::Key;

public:
  /**
   * @brief Creates and returns a certificate for a given key
   * @param key The key for which to make a certificate
   * @param issuer The IssuerId to include in the certificate name
   * @param signingKey The key with which to sign the certificate; if not provided, the
   *                   certificate will be self-signed
   */
  Certificate
  makeCert(const Key& key, const std::string& issuer, const Key& signingKey = Key());

  /**
   * @brief Saves an NDN certificate to a file
   * @return true if successful, false otherwise
   */
  bool
  saveCert(const Data& cert, const std::string& filename);

  /**
   * @brief Saves the default certificate of @p identity to a file
   * @return true if successful, false otherwise
   */
  bool
  saveIdentityCert(const Identity& identity, const std::string& filename);

  /**
   * @brief Saves the default certificate of the identity named @p identityName to a file
   * @param identityName Name of the identity
   * @param filename File name, must be writable
   * @param allowCreate If true, create the identity if it does not exist
   * @return true if successful, false otherwise
   */
  bool
  saveIdentityCert(const Name& identityName, const std::string& filename,
                   bool allowCreate = false);

protected:
  KeyChainFixture();

  ~KeyChainFixture();

protected:
  ndn::KeyChain m_keyChain;

private:
  std::vector<std::string> m_certFiles;
};

} // namespace tests
} // namespace ndn

#endif // NDN_TOOLS_TESTS_KEY_CHAIN_FIXTURE_HPP
