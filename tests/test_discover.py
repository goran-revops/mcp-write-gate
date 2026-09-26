from types import SimpleNamespace

from mcp_write_gate.discover import guess


def tool(name, schema=None, read_only=None):
    hints = SimpleNamespace(read_only_hint=read_only) if read_only is not None else None
    return SimpleNamespace(name=name, input_schema=schema or {}, annotations=hints)


def test_a_hint_can_make_a_tool_a_write_but_not_turn_a_write_name_into_a_read():
    assert guess(tool("getOrCreateContact", read_only=False))[0]["kind"] == "write"
    assert guess(tool("archive_thread", read_only=True))[0]["kind"] == "write"
    assert guess(tool("thread_summary", read_only=True))[0] == {"kind": "read"}


def test_name_verbs():
    assert guess(tool("searchContacts"))[0] == {"kind": "read"}
    assert guess(tool("list-channels"))[0] == {"kind": "read"}
    assert guess(tool("send_email"))[0]["kind"] == "write"


def test_targets_are_found_in_the_input_schema():
    schema = {
        "type": "object",
        "properties": {
            "to": {"type": "array", "items": {"type": "string"}},
            "subject": {"type": "string"},
            "meeting": {"type": "object", "properties": {"attendees": {"type": "array", "items": {"type": "string"}}}},
            "contacts": {"type": "array", "items": {"type": "object", "properties": {"email": {"type": "string"}}}},
            "channel": {"type": "string"},
        },
    }
    spec, note = guess(tool("create_thing", schema))
    assert spec == {
        "kind": "write",
        "targets": ["$.to[*]", "$.meeting.attendees[*]", "$.contacts[*].email", "$.channel"],
    }


def test_a_write_with_no_obvious_target_is_left_without_targets():
    spec, note = guess(tool("purge_records", {"type": "object", "properties": {"confirm": {"type": "boolean"}}}))
    assert spec == {"kind": "write"}
    assert "refused until" in note


def test_real_world_names_from_hosted_servers():
    # Names from a real 170-tool outbound server that marks nothing read-only.
    for name in ("get_campaign_follow_up_reply_rate", "get_domain_block_list", "sp_get_cities", "get_day_wise_positive_reply_stats"):
        assert guess(tool(name))[0] == {"kind": "read"}, name
    for name in ("send_campaign_email_thread", "forward_campaign_email", "update_campaign_status", "push_leads_to_campaign",
                 "resume_lead", "get_or_create_contact_list", "sp_update_metrics", "change_master_inbox_read_status",
                 "sp_save_search", "api_bulk_delete_accounts"):
        assert guess(tool(name))[0]["kind"] == "write", name


def test_to_only_counts_next_to_an_address_word():
    for field in ("toObjectType", "replyDateTo", "time_to_live", "min_time_btw_emails", "email_account_ids", "max_email_per_day"):
        schema = {"type": "object", "properties": {field: {"type": "string"}}}
        assert guess(tool("send_thing", schema))[0].get("targets") is None, field
    for field in ("to", "to_email", "send_to", "reply_to", "to_emails"):
        schema = {"type": "object", "properties": {field: {"type": "string"}}}
        assert guess(tool("send_thing", schema))[0].get("targets") == [f"$.{field}"], field
