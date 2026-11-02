// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <memory>
#include "lib/json.hpp"
#include "lib/rpc_state.hpp"
#include "lib/json_shape.hpp"
#include "lib/program_args.hpp"
#include "lib/rpc_io.hpp"
#include "lib/endpoint_policy.hpp"

#include "lib/httplib.h"

namespace octra {

struct RpcResult {
    bool ok;
    nlohmann::json result;
    std::string error;
    bool replied = false;
    int code = 0;
    int http_status = 0;
};

class RpcClient {
    std::string host_;
    std::string path_;
    bool ssl_;
    int port_;
    bool valid_ = false;
    std::atomic<int> id_{0};
    mutable std::shared_mutex url_mtx_;
    static constexpr std::size_t max_body = 64u * 1024u * 1024u;

    void parse_url(const std::string& url) {
        const auto parsed = endpoint_policy::parse(endpoint_policy::rpc_url(url));
        valid_ = parsed.ok;
        host_ = parsed.host;
        path_ = parsed.target;
        ssl_ = parsed.tls;
        port_ = parsed.port;
    }

    RpcBody request(std::string body, int seconds) const {
        std::string host, path;
        bool tls;
        int port;
        {
            std::shared_lock<std::shared_mutex> lock(url_mtx_);
            if (!valid_) return {{}, "invalid RPC URL"};
            host = host_;
            path = path_;
            tls = ssl_;
            port = port_;
        }
        if (tls) {
            httplib::SSLClient client(host, port);
            if (client.ssl_context()) SSL_CTX_set_default_verify_paths(client.ssl_context());
            client.enable_server_certificate_verification(true);
            return rpc_post(client, path, std::move(body), seconds, max_body);
        }
        httplib::Client client(host, port);
        return rpc_post(client, path, std::move(body), seconds, max_body);
    }

public:
    RpcClient() : path_("/rpc"), ssl_(true), port_(443) {}
    explicit RpcClient(const std::string& url) { parse_url(url); }
    void set_url(const std::string& url) { std::unique_lock<std::shared_mutex> lk(url_mtx_); parse_url(url); }

    RpcResult call(const std::string& method,
                   const nlohmann::json& params = nlohmann::json::array(),
                   int timeout_sec = 30,
                   const std::string& source = "") {
        if (!source.empty() && (method != "octra_transactionsByAddress" ||
            (source != "live" && source != "archive")))
            return {false, {}, "invalid history source"};
        nlohmann::json req;
        req["jsonrpc"] = "2.0";
        req["method"] = method;
        req["params"] = params;
        req["id"] = ++id_;
        if (!source.empty()) req["source"] = source;
        const auto response = request(req.dump(), timeout_sec);
        if (!response.error.empty()) return {false, {}, response.error, false, 0, response.status};
        return parse_response(response.body, req["id"]);
    }

    RpcResult get_balance(const std::string& addr) {
        return call("octra_balance", {addr});
    }

    RpcResult get_account(const std::string& addr, int limit = 20) {
        return call("octra_account", {addr, limit});
    }

    RpcResult get_transaction(const std::string& hash, int seconds = 30) {
        return call("octra_transaction", {hash}, seconds);
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
        return call("octra_encryptedBalance", {addr, sig_b64, pub_b64}, 25);
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

    RpcResult validator_set_proof(int timeout_sec = 10) {
        return call("octra_validatorSetProof", nlohmann::json::array(), timeout_sec);
    }

    RpcResult resource_compute_submit(const nlohmann::json& request, int timeout_sec = 15) {
        return call("octra_circleComputeSubmit", request, timeout_sec);
    }

    RpcResult resource_compute_status(
            const nlohmann::json& request,
            int timeout_sec = 10) {
        return call("octra_circleComputeStatus", request, timeout_sec);
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

    RpcResult circle_view_raw(const std::string& circle_id, const std::string& method,
        const std::string& params, const std::string& addr, const std::string& pub, const std::string& sig) {
        if (!program_args(params)) return {false, {}, "invalid program parameters"};
        const int id = ++id_;
        const auto quote = [](const std::string& text) { return nlohmann::json(text).dump(); };
        const std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id)
            + ",\"method\":\"octra_circleViewAuth\",\"params\":[" + quote(circle_id)
            + "," + quote(method) + "," + params + "," + quote(addr) + "," + quote(pub)
            + "," + quote(sig) + ",false]}";
        const auto response = request(body, 600);
        if (!response.error.empty()) return {false, {}, response.error};
        return parse_response(response.body, id);
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

    RpcResult program_view_raw(const std::string& addr, const std::string& method,
        const std::string& params, const std::string& caller) {
        if (!program_args(params)) return {false, {}, "invalid program parameters"};
        const int id = ++id_;
        const std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id)
            + ",\"method\":\"contract_call\",\"params\":[" + nlohmann::json(addr).dump()
            + "," + nlohmann::json(method).dump() + "," + params + ","
            + nlohmann::json(caller).dump() + "]}";
        const auto response = request(body, 15);
        if (!response.error.empty()) return {false, {}, response.error};
        return parse_response(response.body, id);
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

    RpcResult get_txs_by_address(const std::string& addr, int limit = 50, int offset = 0,
        const std::string& source = "") {
        return call("octra_transactionsByAddress", {addr, limit, offset}, 15, source);
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
        const auto response = request(batch.dump(), timeout_sec);
        JsonShape shape;
        if (!response.error.empty() || !nlohmann::json::sax_parse(response.body, &shape)) {
            for (auto& result : out) result.error = response.error.empty()
                ? "invalid rpc response structure" : response.error;
            return out;
        }
        try {
            auto arr = nlohmann::json::parse(response.body);
            if (!arr.is_array()) {
                for (auto& o : out) o.error = "batch response not array";
                return out;
            }
            std::vector<bool> seen(count, false);
            for (const auto& item : arr) {
                if (!item.is_object() || !item.contains("id") || !item["id"].is_number_integer()
                    || item["id"] < 1 || item["id"] > count) {
                    return std::vector<RpcResult>(count, {false, {}, "invalid batch response id"});
                }
                const size_t id = item["id"].get<size_t>();
                if (seen[id - 1])
                    return std::vector<RpcResult>(count, {false, {}, "duplicate batch response id"});
                seen[id - 1] = true;
                out[id - 1] = parse_response(item.dump(), id);
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

    RpcResult parse_response(const std::string& body, const nlohmann::json& id) {
        try {
            JsonShape shape;
            if (!nlohmann::json::sax_parse(body, &shape))
                return {false, {}, "invalid rpc response structure"};
            auto j = nlohmann::json::parse(body);
            if (!j.is_object() || j.value("jsonrpc", "") != "2.0"
                || !j.contains("id") || !j["id"].is_number_integer() || j["id"] != id
                || j.contains("result") == j.contains("error"))
                return {false, {}, "invalid rpc response"};
            if (j.contains("result"))
                return {true, j["result"], "", true};
            const auto& error = j["error"];
            if (!error.is_object() || !error.contains("code") || !error["code"].is_number_integer()
                || !error.contains("message") || !error["message"].is_string())
                return {false, {}, "invalid rpc error"};
            if (error["code"].is_number_unsigned()
                && error["code"].get<uint64_t>() > static_cast<uint64_t>(std::numeric_limits<int>::max()))
                return {false, {}, "invalid rpc error code"};
            const auto code = error["code"].get<int64_t>();
            if (code < std::numeric_limits<int>::min() || code > std::numeric_limits<int>::max())
                return {false, {}, "invalid rpc error code"};
            return {false, {}, error_message(error), true, int(code)};
        } catch (const std::exception& ex) {
            return {false, {}, std::string("parse error: ") + ex.what()};
        }
    }
};

}