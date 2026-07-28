/*
    This file is part of Octra Wallet (webcli).

    Octra Wallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Octra Wallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Octra Wallet.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2025-2026 Octra Labs
              2025-2026 David A.
              2025-2026 Alex T.
              2025-2026 Vadim S.
              2025-2026 Julia L.
*/

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <memory>
#include "lib/json.hpp"

#include "lib/httplib.h"

namespace octra {

struct RpcResult {
    bool ok;
    nlohmann::json result;
    std::string error;
};

class RpcClient {
    std::string host_;
    std::string path_;
    bool ssl_;
    int port_;
    std::atomic<int> id_{0};
    mutable std::shared_mutex url_mtx_;
    static constexpr std::size_t max_body = 64u * 1024u * 1024u;

    void parse_url(const std::string& url) {
        std::string u = url;
        ssl_ = false;
        port_ = 80;
        if (u.rfind("https://", 0) == 0) {
            ssl_ = true;
            port_ = 443;
            u = u.substr(8);
        } else if (u.rfind("http://", 0) == 0) {
            u = u.substr(7);
        }
        auto slash = u.find('/');
        if (slash != std::string::npos) {
            path_ = u.substr(slash);
            host_ = u.substr(0, slash);
        } else {
            path_ = "/rpc";
            host_ = u;
        }
        auto colon = host_.find(':');
        if (colon != std::string::npos) {
            port_ = std::stoi(host_.substr(colon + 1));
            host_ = host_.substr(0, colon);
        }
    }

public:
    RpcClient() : path_("/rpc"), ssl_(true), port_(443) {}
    explicit RpcClient(const std::string& url) { parse_url(url); }
    void set_url(const std::string& url) { std::unique_lock<std::shared_mutex> lk(url_mtx_); parse_url(url); }

    RpcResult call(const std::string& method,
                   const nlohmann::json& params = nlohmann::json::array(),
                   int timeout_sec = 30) {
        nlohmann::json req;
        req["jsonrpc"] = "2.0";
        req["method"] = method;
        req["params"] = params;
        req["id"] = ++id_;
        std::string body = req.dump();
        httplib::Headers hdrs = {
            {"Content-Type", "application/json"},
            {"User-Agent", "Octra-Wallet/0.04.10"}
        };
        std::string host, path;
        bool ssl;
        int port;
        {
            std::shared_lock<std::shared_mutex> lk(url_mtx_);
            host = host_;
            path = path_;
            ssl = ssl_;
            port = port_;
        }
        const int connect_timeout_sec = timeout_sec < 5 ? timeout_sec : 5;
        if (ssl) {
            httplib::SSLClient cli(host, port);
            cli.set_connection_timeout(connect_timeout_sec, 0);
            cli.set_read_timeout(timeout_sec, 0);
            if (cli.ssl_context()) SSL_CTX_set_default_verify_paths(cli.ssl_context());
            cli.enable_server_certificate_verification(true);
            auto res = cli.Post(path, hdrs, body, "application/json");
            if (!res) return {false, {}, "connection failed"};
            if (res->body.size() > max_body) return {false, {}, "rpc response too large"};
            return parse_response(res->body);
        } else {
            httplib::Client cli(host, port);
            cli.set_connection_timeout(connect_timeout_sec, 0);
            cli.set_read_timeout(timeout_sec, 0);
            auto res = cli.Post(path, hdrs, body, "application/json");
            if (!res) return {false, {}, "connection failed"};
            if (res->body.size() > max_body) return {false, {}, "rpc response too large"};
            return parse_response(res->body);
        }
    }

    RpcResult get_balance(const std::string& addr) {
        return call("octra_balance", {addr});
    }

    RpcResult get_account(const std::string& addr, int limit = 20) {
        return call("octra_account", {addr, limit});
    }

    RpcResult get_transaction(const std::string& hash) {
        return call("octra_transaction", {hash});
    }

    RpcResult submit_tx(const nlohmann::json& tx) {
        return call("octra_submit", nlohmann::json::array({tx}));
    }

    RpcResult get_view_pubkey(const std::string& addr) {
        return call("octra_viewPubkey", {addr});
    }

    RpcResult get_public_key(const std::string& addr) {
        return call("octra_publicKey", {addr});
    }

    RpcResult get_encrypted_balance(const std::string& addr,
                                    const std::string& sig_b64,
                                    const std::string& pub_b64) {
        return call("octra_encryptedBalance", {addr, sig_b64, pub_b64}, 8);
    }

    RpcResult get_encrypted_cipher(const std::string& addr) {
        return call("octra_encryptedCipher", {addr});
    }

    RpcResult register_pvac_pubkey(const std::string& addr,
                                   const std::string& pk_b64,
                                   const std::string& sig_b64,
                                   const std::string& pub_b64,
                                   const std::string& aes_kat_hex = "") {
        return call("octra_registerPvacPubkey", {addr, pk_b64, sig_b64, pub_b64, aes_kat_hex});
    }

    RpcResult get_pvac_pubkey(const std::string& addr, int timeout_sec = 30) {
        return call("octra_pvacPubkey", {addr}, timeout_sec);
    }

    RpcResult get_pvac_migration_status(const std::string& addr, int timeout_sec = 30) {
        return call("octra_pvacMigrationStatus", {addr}, timeout_sec);
    }

    RpcResult node_status(int timeout_sec = 5) {
        return call("node_status", nlohmann::json::array(), timeout_sec);
    }

    RpcResult register_public_key(const std::string& addr,
                                   const std::string& pub_b64,
                                   const std::string& sig_b64) {
        return call("octra_registerPublicKey", {addr, pub_b64, sig_b64});
    }

    RpcResult get_stealth_outputs(int from_epoch = 0, int timeout_sec = 30) {
        return call("octra_stealthOutputs", {from_epoch}, timeout_sec);
    }

    RpcResult get_stealth_outputs_page(int from_epoch,
                                       int64_t before_id,
                                       int limit = 256,
                                       int timeout_sec = 10) {
        nlohmann::json before = before_id < 0 ? nlohmann::json(nullptr) : nlohmann::json(before_id);
        return call("octra_stealthOutputsPage", {from_epoch, before, limit}, timeout_sec);
    }

    RpcResult get_stealth_outputs_by_id(const nlohmann::json& ids, int timeout_sec = 10) {
        return call("octra_stealthOutputsById", nlohmann::json::array({ids}), timeout_sec);
    }

    RpcResult staging_view() {
        return call("staging_view", nlohmann::json::array(), 5);
    }

    RpcResult compile_assembly(const std::string& source) {
        return call("octra_compileAssembly", {source}, 10);
    }

    RpcResult compile_aml(const std::string& source, bool program) {
        return call("octra_compileAml", {source, program}, 10);
    }

    RpcResult compile_aml_multi(
        const nlohmann::json& files,
        const std::string& main_path,
        bool program) {
        nlohmann::json payload;
        payload["files"] = files;
        payload["main"] = main_path;
        payload["program"] = program;
        return call("octra_compileAmlMulti", nlohmann::json::array({payload}), 15);
    }

    RpcResult compute_contract_address(const std::string& bytecode_b64,
                                        const std::string& deployer,
                                        int nonce = 0) {
        return call("octra_computeContractAddress", {bytecode_b64, deployer, nonce});
    }

    RpcResult vm_contract(const std::string& addr) {
        return call("vm_contract", {addr});
    }

    RpcResult circle_info(const std::string& circle_id) {
        return call("circle_info", {circle_id}, 10);
    }

    RpcResult circle_info_auth(const std::string& circle_id,
                               const std::string& addr,
                               const std::string& pub_b64,
                               const std::string& sig_b64) {
        return call("octra_circleInfoAuth", {circle_id, addr, pub_b64, sig_b64}, 10);
    }

    RpcResult circle_program_info(const std::string& circle_id) {
        return call("octra_circleProgramInfo", {circle_id}, 15);
    }

    RpcResult circle_program_info_auth(const std::string& circle_id,
                                       const std::string& addr,
                                       const std::string& pub_b64,
                                       const std::string& sig_b64) {
        return call("octra_circleProgramInfoAuth", {circle_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_view(const std::string& circle_id,
                          const std::string& method,
                          const nlohmann::json& params,
                          const std::string& caller,
                          bool include_storage = false) {
        return call("octra_circleView", {circle_id, method, params, caller, include_storage}, 600);
    }

    RpcResult circle_view_auth(const std::string& circle_id,
                               const std::string& method,
                               const nlohmann::json& params,
                               const std::string& addr,
                               const std::string& pub_b64,
                               const std::string& sig_b64,
                               bool include_storage = false) {
        return call("octra_circleViewAuth", {circle_id, method, params, addr, pub_b64, sig_b64, include_storage}, 600);
    }

    RpcResult circle_slot_policy(const std::string& circle_id, const std::string& slot_ref) {
        return call("octra_circleSlotPolicy", {circle_id, slot_ref}, 15);
    }

    RpcResult circle_slot_policy_auth(const std::string& circle_id,
                                      const std::string& slot_ref,
                                      const std::string& addr,
                                      const std::string& pub_b64,
                                      const std::string& sig_b64) {
        return call("octra_circleSlotPolicyAuth", {circle_id, slot_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_state_policy(const std::string& circle_id, const std::string& state_ref) {
        return call("octra_circleStatePolicy", {circle_id, state_ref}, 15);
    }

    RpcResult circle_state_policy_auth(const std::string& circle_id,
                                       const std::string& state_ref,
                                       const std::string& addr,
                                       const std::string& pub_b64,
                                       const std::string& sig_b64) {
        return call("octra_circleStatePolicyAuth", {circle_id, state_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_state_descriptor(const std::string& circle_id, const std::string& state_ref) {
        return call("octra_circleStateDescriptor", {circle_id, state_ref}, 15);
    }

    RpcResult circle_state_descriptor_auth(const std::string& circle_id,
                                           const std::string& state_ref,
                                           const std::string& addr,
                                           const std::string& pub_b64,
                                           const std::string& sig_b64) {
        return call("octra_circleStateDescriptorAuth", {circle_id, state_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_balance_cell(const std::string& circle_id, const std::string& state_ref) {
        return call("octra_circleBalanceCell", {circle_id, state_ref}, 15);
    }

    RpcResult circle_balance_cell_auth(const std::string& circle_id,
                                       const std::string& state_ref,
                                       const std::string& addr,
                                       const std::string& pub_b64,
                                       const std::string& sig_b64) {
        return call("octra_circleBalanceCellAuth", {circle_id, state_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_register_cell(const std::string& circle_id, const std::string& state_ref) {
        return call("octra_circleRegisterCell", {circle_id, state_ref}, 15);
    }

    RpcResult circle_register_cell_auth(const std::string& circle_id,
                                        const std::string& state_ref,
                                        const std::string& addr,
                                        const std::string& pub_b64,
                                        const std::string& sig_b64) {
        return call("octra_circleRegisterCellAuth", {circle_id, state_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_balance_binding(const std::string& circle_id, const std::string& subject_addr) {
        return call("octra_circleBalanceBinding", {circle_id, subject_addr}, 15);
    }

    RpcResult circle_balance_binding_auth(const std::string& circle_id,
                                          const std::string& subject_addr,
                                          const std::string& addr,
                                          const std::string& pub_b64,
                                          const std::string& sig_b64) {
        return call("octra_circleBalanceBindingAuth", {circle_id, subject_addr, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_register_binding(const std::string& circle_id, const std::string& register_ref) {
        return call("octra_circleRegisterBinding", {circle_id, register_ref}, 15);
    }

    RpcResult circle_register_binding_auth(const std::string& circle_id,
                                           const std::string& register_ref,
                                           const std::string& addr,
                                           const std::string& pub_b64,
                                           const std::string& sig_b64) {
        return call("octra_circleRegisterBindingAuth", {circle_id, register_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_balance_workflow(const std::string& circle_id, const std::string& workflow_ref) {
        return call("octra_circleBalanceWorkflow", {circle_id, workflow_ref}, 15);
    }

    RpcResult circle_balance_workflow_auth(const std::string& circle_id,
                                           const std::string& workflow_ref,
                                           const std::string& addr,
                                           const std::string& pub_b64,
                                           const std::string& sig_b64) {
        return call("octra_circleBalanceWorkflowAuth", {circle_id, workflow_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_register_workflow(const std::string& circle_id, const std::string& workflow_ref) {
        return call("octra_circleRegisterWorkflow", {circle_id, workflow_ref}, 15);
    }

    RpcResult circle_register_workflow_auth(const std::string& circle_id,
                                            const std::string& workflow_ref,
                                            const std::string& addr,
                                            const std::string& pub_b64,
                                            const std::string& sig_b64) {
        return call("octra_circleRegisterWorkflowAuth", {circle_id, workflow_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_object_summary(const std::string& circle_id, const std::string& object_ref) {
        return call("octra_circleObjectSummary", {circle_id, object_ref}, 15);
    }

    RpcResult circle_object_summary_auth(const std::string& circle_id,
                                         const std::string& object_ref,
                                         const std::string& addr,
                                         const std::string& pub_b64,
                                         const std::string& sig_b64) {
        return call("octra_circleObjectSummaryAuth", {circle_id, object_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_object_members(const std::string& circle_id, const std::string& object_ref) {
        return call("octra_circleObjectMembers", {circle_id, object_ref}, 15);
    }

    RpcResult circle_object_members_auth(const std::string& circle_id,
                                         const std::string& object_ref,
                                         const std::string& addr,
                                         const std::string& pub_b64,
                                         const std::string& sig_b64) {
        return call("octra_circleObjectMembersAuth", {circle_id, object_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_object_detail(const std::string& circle_id, const std::string& object_ref) {
        return call("octra_circleObjectDetail", {circle_id, object_ref}, 15);
    }

    RpcResult circle_object_detail_auth(const std::string& circle_id,
                                        const std::string& object_ref,
                                        const std::string& addr,
                                        const std::string& pub_b64,
                                        const std::string& sig_b64) {
        return call("octra_circleObjectDetailAuth", {circle_id, object_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_object_member(const std::string& circle_id,
                                   const std::string& object_ref,
                                   const std::string& member_ref) {
        return call("octra_circleObjectMember", {circle_id, object_ref, member_ref}, 15);
    }

    RpcResult circle_object_member_auth(const std::string& circle_id,
                                        const std::string& object_ref,
                                        const std::string& member_ref,
                                        const std::string& addr,
                                        const std::string& pub_b64,
                                        const std::string& sig_b64) {
        return call("octra_circleObjectMemberAuth", {circle_id, object_ref, member_ref, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_object_refs(const std::string& circle_id) {
        return call("octra_circleObjectRefs", {circle_id}, 15);
    }

    RpcResult circle_object_refs_auth(const std::string& circle_id,
                                      const std::string& addr,
                                      const std::string& pub_b64,
                                      const std::string& sig_b64) {
        return call("octra_circleObjectRefsAuth", {circle_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_object_list(const std::string& circle_id) {
        return call("octra_circleObjectList", {circle_id}, 15);
    }

    RpcResult circle_object_list_auth(const std::string& circle_id,
                                      const std::string& addr,
                                      const std::string& pub_b64,
                                      const std::string& sig_b64) {
        return call("octra_circleObjectListAuth", {circle_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_transport_policy(const std::string& circle_id) {
        return call("octra_circleTransportPolicy", {circle_id}, 15);
    }

    RpcResult circle_transport_policy_auth(const std::string& circle_id,
                                           const std::string& addr,
                                           const std::string& pub_b64,
                                           const std::string& sig_b64) {
        return call("octra_circleTransportPolicyAuth", {circle_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_hfhe_policy(const std::string& circle_id) {
        return call("octra_circleHfhePolicy", {circle_id}, 15);
    }

    RpcResult circle_hfhe_policy_auth(const std::string& circle_id,
                                      const std::string& addr,
                                      const std::string& pub_b64,
                                      const std::string& sig_b64) {
        return call("octra_circleHfhePolicyAuth", {circle_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_key_policy(const std::string& circle_id, const std::string& key_id) {
        return call("octra_circleKeyPolicy", {circle_id, key_id}, 15);
    }

    RpcResult circle_key_policy_auth(const std::string& circle_id,
                                     const std::string& key_id,
                                     const std::string& addr,
                                     const std::string& pub_b64,
                                     const std::string& sig_b64) {
        return call("octra_circleKeyPolicyAuth", {circle_id, key_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_storage(const std::string& circle_id, const std::string& key) {
        return call("octra_circleStorage", {circle_id, key}, 15);
    }

    RpcResult circle_storage_auth(const std::string& circle_id,
                                  const std::string& key,
                                  const std::string& addr,
                                  const std::string& pub_b64,
                                  const std::string& sig_b64) {
        return call("octra_circleStorageAuth", {circle_id, key, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_storage_dump(const std::string& circle_id) {
        return call("octra_circleStorageDump", {circle_id}, 15);
    }

    RpcResult circle_storage_dump_auth(const std::string& circle_id,
                                       const std::string& addr,
                                       const std::string& pub_b64,
                                       const std::string& sig_b64) {
        return call("octra_circleStorageDumpAuth", {circle_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_outbox_intent(const std::string& circle_id, const std::string& intent_id) {
        return call("octra_circleOutboxIntent", {circle_id, intent_id}, 15);
    }

    RpcResult circle_outbox_claim(const std::string& circle_id, const std::string& intent_id) {
        return call("octra_circleOutboxClaim", {circle_id, intent_id}, 15);
    }

    RpcResult circle_outbox_claim_auth(const std::string& circle_id,
                                       const std::string& intent_id,
                                       const std::string& addr,
                                       const std::string& pub_b64,
                                       const std::string& sig_b64) {
        return call("octra_circleOutboxClaimAuth", {circle_id, intent_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_outbox_intent_auth(const std::string& circle_id,
                                        const std::string& intent_id,
                                        const std::string& addr,
                                        const std::string& pub_b64,
                                        const std::string& sig_b64) {
        return call("octra_circleOutboxIntentAuth", {circle_id, intent_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_outbox_status(const std::string& circle_id, const std::string& intent_id) {
        return call("octra_circleOutboxStatus", {circle_id, intent_id}, 15);
    }

    RpcResult circle_outbox_status_auth(const std::string& circle_id,
                                        const std::string& intent_id,
                                        const std::string& addr,
                                        const std::string& pub_b64,
                                        const std::string& sig_b64) {
        return call("octra_circleOutboxStatusAuth", {circle_id, intent_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_ingress_packet(const std::string& circle_id, const std::string& intent_id) {
        return call("octra_circleIngressPacket", {circle_id, intent_id}, 15);
    }

    RpcResult circle_ingress_packet_auth(const std::string& circle_id,
                                         const std::string& intent_id,
                                         const std::string& addr,
                                         const std::string& pub_b64,
                                         const std::string& sig_b64) {
        return call("octra_circleIngressPacketAuth", {circle_id, intent_id, addr, pub_b64, sig_b64}, 15);
    }

    RpcResult circle_asset(const std::string& circle_id, const std::string& path) {
        return call("circle_asset", {circle_id, path}, 10);
    }

    RpcResult circle_asset_ciphertext(const std::string& circle_id, const std::string& path) {
        return call("circle_asset_ciphertext", {circle_id, path}, 10);
    }

    RpcResult circle_asset_ciphertext_auth(const std::string& circle_id,
                                           const std::string& path,
                                           const std::string& addr,
                                           const std::string& pub_b64,
                                           const std::string& sig_b64) {
        return call("octra_circleAssetCiphertextAuth", {circle_id, path, addr, pub_b64, sig_b64}, 10);
    }

    RpcResult circle_asset_ciphertext_by_resource_key(const std::string& circle_id, const std::string& resource_key) {
        return call("circle_asset_ciphertext_by_resource_key", {circle_id, resource_key}, 10);
    }

    RpcResult circle_asset_ciphertext_by_resource_key_auth(const std::string& circle_id,
                                                           const std::string& resource_key,
                                                           const std::string& addr,
                                                           const std::string& pub_b64,
                                                           const std::string& sig_b64) {
        return call("octra_circleAssetCiphertextByResourceKeyAuth", {circle_id, resource_key, addr, pub_b64, sig_b64}, 10);
    }

    RpcResult circle_asset_ciphertext_by_slot_ref(const std::string& circle_id, const std::string& slot_ref) {
        return call("circle_asset_ciphertext_by_slot_ref", {circle_id, slot_ref}, 10);
    }

    RpcResult circle_asset_ciphertext_by_slot_ref_auth(const std::string& circle_id,
                                                       const std::string& slot_ref,
                                                       const std::string& addr,
                                                       const std::string& pub_b64,
                                                       const std::string& sig_b64) {
        return call("octra_circleAssetCiphertextBySlotRefAuth", {circle_id, slot_ref, addr, pub_b64, sig_b64}, 10);
    }

    RpcResult circle_asset_ciphertext_by_state_ref(const std::string& circle_id, const std::string& state_ref) {
        return call("octra_circleAssetCiphertextByStateRef", {circle_id, state_ref}, 10);
    }

    RpcResult circle_asset_ciphertext_by_state_ref_auth(const std::string& circle_id,
                                                        const std::string& state_ref,
                                                        const std::string& addr,
                                                        const std::string& pub_b64,
                                                        const std::string& sig_b64) {
        return call("octra_circleAssetCiphertextByStateRefAuth", {circle_id, state_ref, addr, pub_b64, sig_b64}, 10);
    }

    RpcResult contract_receipt(const std::string& hash) {
        return call("contract_receipt", {hash});
    }

    RpcResult contract_call_view(const std::string& addr,
                                  const std::string& method,
                                  const nlohmann::json& params,
                                  const std::string& caller) {
        return call("contract_call", {addr, method, params, caller}, 15);
    }

    RpcResult list_contracts() {
        return call("octra_listContracts", nlohmann::json::array(), 10);
    }

    RpcResult tokens_by_address(const std::string& addr) {
        return call("octra_tokensByAddress", {addr}, 15);
    }

    RpcResult contract_storage(const std::string& addr, const std::string& key, const std::string& limit = "") {
        if (limit.empty()) return call("octra_contractStorage", {addr, key});
        return call("octra_contractStorage", {addr, key, limit});
    }

    RpcResult contract_abi(const std::string& addr) {
        return call("octra_contractAbi", {addr});
    }

    RpcResult save_abi(const std::string& addr, const std::string& abi) {
        return call("contract_saveAbi", {addr, abi});
    }

    RpcResult get_txs_by_address(const std::string& addr, int limit = 50, int offset = 0) {
        return call("octra_transactionsByAddress", {addr, limit, offset}, 15);
    }

    RpcResult get_token_txs_by_address(const std::string& addr, int limit = 50, int offset = 0) {
        return call("octra_tokenTransfersByAddress", {addr, limit, offset}, 30);
    }

    std::vector<RpcResult> call_batch(const std::vector<std::string>& methods,
                                      const std::vector<nlohmann::json>& params_list = {},
                                      int timeout_sec = 10) {
        size_t count = methods.size();
        std::vector<RpcResult> out(count, {false, {}, "no response"});
        if (count == 0) return out;
        nlohmann::json batch = nlohmann::json::array();
        for (size_t i = 0; i < count; ++i) {
            nlohmann::json req;
            req["jsonrpc"] = "2.0";
            req["method"] = methods[i];
            req["params"] = (i < params_list.size()) ? params_list[i] : nlohmann::json::array();
            req["id"] = static_cast<int>(i + 1);
            batch.push_back(std::move(req));
        }
        std::string body = batch.dump();
        httplib::Headers hdrs = {
            {"Content-Type", "application/json"},
            {"User-Agent", "Octra-Wallet/0.04.10"}
        };
        std::string resp_body;
        std::string host, path;
        bool ssl;
        int port;
        {
            std::shared_lock<std::shared_mutex> lk(url_mtx_);
            host = host_;
            path = path_;
            ssl = ssl_;
            port = port_;
        }
        const int connect_timeout_sec = timeout_sec < 5 ? timeout_sec : 5;
        if (ssl) {
            httplib::SSLClient cli(host, port);
            cli.set_connection_timeout(connect_timeout_sec, 0);
            cli.set_read_timeout(timeout_sec, 0);
            if (cli.ssl_context()) SSL_CTX_set_default_verify_paths(cli.ssl_context());
            cli.enable_server_certificate_verification(true);
            auto r = cli.Post(path, hdrs, body, "application/json");
            if (!r) { for (auto& o : out) o.error = "connection failed"; return out; }
            if (r->body.size() > max_body) { for (auto& o : out) o.error = "rpc response too large"; return out; }
            resp_body = r->body;
        } else {
            httplib::Client cli(host, port);
            cli.set_connection_timeout(connect_timeout_sec, 0);
            cli.set_read_timeout(timeout_sec, 0);
            auto r = cli.Post(path, hdrs, body, "application/json");
            if (!r) { for (auto& o : out) o.error = "connection failed"; return out; }
            if (r->body.size() > max_body) { for (auto& o : out) o.error = "rpc response too large"; return out; }
            resp_body = r->body;
        }
        try {
            auto arr = nlohmann::json::parse(resp_body);
            if (!arr.is_array()) {
                for (auto& o : out) o.error = "batch response not array";
                return out;
            }
            for (auto& item : arr) {
                if (!item.contains("id") || !item["id"].is_number_integer()) continue;
                int id = item["id"].get<int>();
                if (id < 1 || id > static_cast<int>(count)) continue;
                if (item.contains("result")) {
                    out[id - 1] = {true, item["result"], ""};
                } else if (item.contains("error")) {
                    out[id - 1] = {
                        false,
                        {},
                        error_message(item["error"])
                    };
                }
            }
        } catch (const std::exception& ex) {
            for (auto& o : out) o.error = std::string("parse error: ") + ex.what();
        }
        return out;
    }

private:
    static std::string error_message(const nlohmann::json& error) {
        if (!error.is_object()) return error.dump();
        std::string message = error.value("message", "rpc error");
        auto data = error.find("data");
        if (data != error.end() && data->is_string()) {
            std::string detail = data->get<std::string>();
            if (!detail.empty() && detail != message)
                message += ": " + detail;
        }
        return message;
    }

    RpcResult parse_response(const std::string& body) {
        try {
            auto j = nlohmann::json::parse(body);
            if (j.contains("result"))
                return {true, j["result"], ""};
            if (j.contains("error"))
                return {false, {}, error_message(j["error"])};
            return {false, {}, "unknown rpc response"};
        } catch (const std::exception& ex) {
            return {false, {}, std::string("parse error: ") + ex.what()};
        }
    }
};

}