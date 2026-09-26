from mcp_write_gate.targets import extract, keys


def test_paths_reach_strings_lists_and_nested_objects():
    call = {
        "to": ["A <a@x.com>", "b@y.com"],
        "cc": "c@z.com, d@z.com",
        "message": {"recipients": [{"email": "e@w.com", "name": "E"}, {"address": "f@v.com"}]},
        "channel": "#General",
    }
    assert extract(call, ["$.to[*]"]) == ["a@x.com", "b@y.com"]
    assert extract(call, ["cc"]) == ["c@z.com", "d@z.com"]
    assert extract(call, ["$.message.recipients[*].email"]) == ["e@w.com"]
    assert extract(call, ["$.message.recipients"]) == ["e@w.com", "f@v.com"]
    assert extract(call, ["$.channel", "$.missing", "$.to[0]"]) == ["#General", "a@x.com"]


def test_a_path_through_a_list_without_star_still_reaches_every_item():
    assert extract({"to": [{"email": "a@x.com"}, {"email": "b@x.com"}]}, ["$.to.email"]) == ["a@x.com", "b@x.com"]


def test_keys_go_from_most_specific_to_parent_domains():
    assert keys("CEO <CEO@eu.Acme.co.uk>") == ["ceo@eu.acme.co.uk", "eu.acme.co.uk", "acme.co.uk", "co.uk"]
    assert keys("https://www.acme.com/pricing") == ["acme.com"]
    assert keys("acme.com.") == ["acme.com"]
    assert keys("#Sales") == ["#sales"]
    assert keys("C0123") == ["c0123"]


def test_a_string_where_a_list_was_expected_is_still_checked():
    assert extract({"cc": "ceo@acme.com"}, ["$.cc[*]"]) == ["ceo@acme.com"]
    assert extract({"to": "a@new.com; ceo@acme.com"}, ["$.to[*]"]) == ["a@new.com", "ceo@acme.com"]


def test_nested_recipient_objects():
    call = {"toRecipients": [{"emailAddress": {"name": "C", "address": "ceo@acme.com"}}]}
    assert extract(call, ["$.toRecipients"]) == ["ceo@acme.com"]
