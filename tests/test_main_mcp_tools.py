"""
Tests for bloodhound_mcp composite tools in main.py.

Architecture: main.py exposes 11 composite MCP tools. Each tool accepts an
info_type parameter that dispatches to the appropriate BloodHound API method
via _handle_tool_call(). Tests mock bloodhound_api at the module level so no
live BH CE instance is needed.

Tools covered:
    domain_info, user_info, group_info, computer_info, ou_info, gpo_info,
    graph_analysis, adcs_info, cypher_query, data_quality, custom_nodes,
    asset_groups

Helper covered:
    _handle_tool_call (dispatch, unknown info_type, error propagation)
"""

import json
import sys
import os
from unittest.mock import patch, MagicMock

import pytest

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import main
from lib.bloodhound_api import BloodhoundAPIError, BloodhoundConnectionError


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

DOMAIN_ID = "S-1-5-21-111111111-222222222-333333333"
USER_ID = "S-1-5-21-111111111-222222222-333333333-1234"
GROUP_ID = "S-1-5-21-111111111-222222222-333333333-512"
COMPUTER_ID = "S-1-5-21-111111111-222222222-333333333-1001"
OU_ID = "1A2B3C4D-1234-5678-ABCD-1234567890AB"
GPO_ID = "5E6F7A8B-1234-5678-ABCD-1234567890AB"
TEMPLATE_ID = "9C0D1E2F-1234-5678-ABCD-1234567890AB"
CA_ID = "3A4B5C6D-1234-5678-ABCD-1234567890AB"
QUERY_ID = "42"


def make_api_error(status_code: int) -> BloodhoundAPIError:
    response = MagicMock()
    response.status_code = status_code
    return BloodhoundAPIError(f"HTTP {status_code}", response)


def make_api_error_with_body(
    status_code: int | None,
    body: dict | str | None = None,
    response_status_code: int | None = None,
) -> BloodhoundAPIError:
    response = MagicMock()
    if response_status_code is None and status_code is None:
        response = None
    else:
        response.status_code = (
            response_status_code if response_status_code is not None else status_code
        )
        if isinstance(body, dict):
            response.json.return_value = body
            response.text = json.dumps(body)
        elif isinstance(body, str):
            response.json.side_effect = ValueError("not json")
            response.text = body
        else:
            response.json.side_effect = ValueError("not json")
            response.text = ""

    error = BloodhoundAPIError(f"HTTP {status_code}", response)
    error.status_code = status_code
    return error


# ---------------------------------------------------------------------------
# _handle_tool_call
# ---------------------------------------------------------------------------


class TestHandleToolCall:
    def test_dispatches_to_correct_handler(self):
        handlers = {
            "foo": lambda: {"key": "value"},
            "bar": lambda: {"key": "other"},
        }
        result = json.loads(main._handle_tool_call("foo", handlers))
        assert result["info_type"] == "foo"
        assert result["data"] == {"key": "value"}

    def test_unknown_info_type_returns_error(self):
        handlers = {"a": lambda: {}, "b": lambda: {}}
        result = json.loads(main._handle_tool_call("z", handlers))
        assert "error" in result
        assert "z" in result["error"]
        assert "a" in result["error"]

    def test_context_kwargs_included_in_response(self):
        handlers = {"x": lambda: []}
        result = json.loads(main._handle_tool_call("x", handlers, user_id="U1"))
        assert result["user_id"] == "U1"

    def test_connection_error_returns_error_json(self):
        def boom():
            raise BloodhoundConnectionError("unreachable")

        result = json.loads(main._handle_tool_call("bad", {"bad": boom}))
        assert "error" in result
        assert "Connection error" in result["error"]

    def test_api_error_returns_error_json(self):
        def boom():
            raise make_api_error(403)

        result = json.loads(main._handle_tool_call("bad", {"bad": boom}))
        assert "error" in result
        assert "403" in result["error"]

    def test_unexpected_error_returns_error_json(self):
        def boom():
            raise ValueError("something broke")

        result = json.loads(main._handle_tool_call("bad", {"bad": boom}))
        assert "error" in result


# ---------------------------------------------------------------------------
# domain_info
# ---------------------------------------------------------------------------


class TestDomainInfo:
    @patch("main.bloodhound_api")
    def test_list(self, api):
        api.domains.get_all.return_value = [{"name": "CORP.LOCAL"}]
        result = json.loads(main.domain_info(info_type="list"))
        assert result["info_type"] == "list"
        assert result["data"] == [{"name": "CORP.LOCAL"}]
        api.domains.get_all.assert_called_once()

    @patch("main.bloodhound_api")
    def test_search(self, api):
        api.domains.search_objects.return_value = [{"name": "JDOE"}]
        result = json.loads(main.domain_info(info_type="search", query="JDOE"))
        assert result["info_type"] == "search"
        api.domains.search_objects.assert_called_once_with(
            "JDOE", None, limit=100, skip=0
        )

    @patch("main.bloodhound_api")
    def test_users(self, api):
        api.domains.get_users.return_value = []
        result = json.loads(main.domain_info(info_type="users", domain_id=DOMAIN_ID))
        assert result["info_type"] == "users"
        api.domains.get_users.assert_called_once_with(DOMAIN_ID, limit=100, skip=0)

    @patch("main.bloodhound_api")
    def test_groups(self, api):
        api.domains.get_groups.return_value = []
        result = json.loads(main.domain_info(info_type="groups", domain_id=DOMAIN_ID))
        assert result["info_type"] == "groups"

    @patch("main.bloodhound_api")
    def test_computers(self, api):
        api.domains.get_computers.return_value = []
        result = json.loads(
            main.domain_info(info_type="computers", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "computers"

    @patch("main.bloodhound_api")
    def test_controllers(self, api):
        api.domains.get_controllers.return_value = []
        result = json.loads(
            main.domain_info(info_type="controllers", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "controllers"

    @patch("main.bloodhound_api")
    def test_gpos(self, api):
        api.domains.get_gpos.return_value = []
        result = json.loads(main.domain_info(info_type="gpos", domain_id=DOMAIN_ID))
        assert result["info_type"] == "gpos"

    @patch("main.bloodhound_api")
    def test_ous(self, api):
        api.domains.get_ous.return_value = []
        result = json.loads(main.domain_info(info_type="ous", domain_id=DOMAIN_ID))
        assert result["info_type"] == "ous"

    @patch("main.bloodhound_api")
    def test_dc_syncers(self, api):
        api.domains.get_dc_syncers.return_value = []
        result = json.loads(
            main.domain_info(info_type="dc_syncers", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "dc_syncers"

    @patch("main.bloodhound_api")
    def test_foreign_admins(self, api):
        api.domains.get_foreign_admins.return_value = []
        result = json.loads(
            main.domain_info(info_type="foreign_admins", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "foreign_admins"

    @patch("main.bloodhound_api")
    def test_foreign_gpo_controllers(self, api):
        api.domains.get_foreign_gpo_controllers.return_value = []
        result = json.loads(
            main.domain_info(info_type="foreign_gpo_controllers", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "foreign_gpo_controllers"

    @patch("main.bloodhound_api")
    def test_foreign_groups(self, api):
        api.domains.get_foreign_groups.return_value = []
        result = json.loads(
            main.domain_info(info_type="foreign_groups", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "foreign_groups"

    @patch("main.bloodhound_api")
    def test_foreign_users(self, api):
        api.domains.get_foreign_users.return_value = []
        result = json.loads(
            main.domain_info(info_type="foreign_users", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "foreign_users"

    @patch("main.bloodhound_api")
    def test_inbound_trusts(self, api):
        api.domains.get_inbound_trusts.return_value = []
        result = json.loads(
            main.domain_info(info_type="inbound_trusts", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "inbound_trusts"

    @patch("main.bloodhound_api")
    def test_outbound_trusts(self, api):
        api.domains.get_outbound_trusts.return_value = []
        result = json.loads(
            main.domain_info(info_type="outbound_trusts", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "outbound_trusts"

    @patch("main.bloodhound_api")
    def test_pagination_params_forwarded(self, api):
        api.domains.get_users.return_value = []
        main.domain_info(info_type="users", domain_id=DOMAIN_ID, limit=25, skip=50)
        api.domains.get_users.assert_called_once_with(DOMAIN_ID, limit=25, skip=50)

    def test_unknown_info_type(self):
        result = json.loads(main.domain_info(info_type="nonexistent"))
        assert "error" in result

    @patch("main.bloodhound_api")
    def test_api_error_propagates(self, api):
        api.domains.get_all.side_effect = make_api_error(500)
        result = json.loads(main.domain_info(info_type="list"))
        assert "error" in result
        assert "500" in result["error"]


# ---------------------------------------------------------------------------
# user_info
# ---------------------------------------------------------------------------


class TestUserInfo:
    @patch("main.bloodhound_api")
    def test_info(self, api):
        api.users.get_info.return_value = {"name": "JDOE@CORP.LOCAL", "enabled": True}
        result = json.loads(main.user_info(USER_ID, info_type="info"))
        assert result["info_type"] == "info"
        assert result["user_id"] == USER_ID
        api.users.get_info.assert_called_once_with(USER_ID)

    @patch("main.bloodhound_api")
    def test_admin_rights(self, api):
        api.users.get_admin_rights.return_value = []
        result = json.loads(main.user_info(USER_ID, info_type="admin_rights"))
        assert result["info_type"] == "admin_rights"
        api.users.get_admin_rights.assert_called_once_with(USER_ID, limit=100, skip=0)

    @patch("main.bloodhound_api")
    def test_constrained_delegation(self, api):
        api.users.get_constrained_delegation_rights.return_value = []
        result = json.loads(
            main.user_info(USER_ID, info_type="constrained_delegation")
        )
        assert result["info_type"] == "constrained_delegation"

    @patch("main.bloodhound_api")
    def test_controllables(self, api):
        api.users.get_controllables.return_value = []
        result = json.loads(main.user_info(USER_ID, info_type="controllables"))
        assert result["info_type"] == "controllables"

    @patch("main.bloodhound_api")
    def test_controllers(self, api):
        api.users.get_controllers.return_value = []
        result = json.loads(main.user_info(USER_ID, info_type="controllers"))
        assert result["info_type"] == "controllers"

    @patch("main.bloodhound_api")
    def test_dcom_rights(self, api):
        api.users.get_dcom_rights.return_value = []
        result = json.loads(main.user_info(USER_ID, info_type="dcom_rights"))
        assert result["info_type"] == "dcom_rights"

    @patch("main.bloodhound_api")
    def test_memberships(self, api):
        api.users.get_memberships.return_value = [{"name": "DOMAIN ADMINS@CORP.LOCAL"}]
        result = json.loads(main.user_info(USER_ID, info_type="memberships"))
        assert result["info_type"] == "memberships"
        assert len(result["data"]) == 1

    @patch("main.bloodhound_api")
    def test_ps_remote_rights(self, api):
        api.users.get_ps_remote_rights.return_value = []
        result = json.loads(main.user_info(USER_ID, info_type="ps_remote_rights"))
        assert result["info_type"] == "ps_remote_rights"

    @patch("main.bloodhound_api")
    def test_rdp_rights(self, api):
        api.users.get_rdp_rights.return_value = []
        result = json.loads(main.user_info(USER_ID, info_type="rdp_rights"))
        assert result["info_type"] == "rdp_rights"

    @patch("main.bloodhound_api")
    def test_sessions(self, api):
        api.users.get_sessions.return_value = []
        result = json.loads(main.user_info(USER_ID, info_type="sessions"))
        assert result["info_type"] == "sessions"

    @patch("main.bloodhound_api")
    def test_sql_admin_rights(self, api):
        api.users.get_sql_admin_rights.return_value = []
        result = json.loads(main.user_info(USER_ID, info_type="sql_admin_rights"))
        assert result["info_type"] == "sql_admin_rights"

    def test_unknown_info_type(self):
        result = json.loads(main.user_info(USER_ID, info_type="bad"))
        assert "error" in result

    @patch("main.bloodhound_api")
    def test_user_id_in_context(self, api):
        api.users.get_info.return_value = {}
        result = json.loads(main.user_info(USER_ID, info_type="info"))
        assert result["user_id"] == USER_ID


# ---------------------------------------------------------------------------
# group_info
# ---------------------------------------------------------------------------


class TestGroupInfo:
    @patch("main.bloodhound_api")
    def test_info(self, api):
        api.groups.get_info.return_value = {"name": "DOMAIN ADMINS@CORP.LOCAL"}
        result = json.loads(main.group_info(GROUP_ID, info_type="info"))
        assert result["info_type"] == "info"
        assert result["group_id"] == GROUP_ID

    @patch("main.bloodhound_api")
    def test_admin_rights(self, api):
        api.groups.get_admin_rights.return_value = []
        result = json.loads(main.group_info(GROUP_ID, info_type="admin_rights"))
        assert result["info_type"] == "admin_rights"

    @patch("main.bloodhound_api")
    def test_controllables(self, api):
        api.groups.get_controllables.return_value = []
        result = json.loads(main.group_info(GROUP_ID, info_type="controllables"))
        assert result["info_type"] == "controllables"

    @patch("main.bloodhound_api")
    def test_controllers(self, api):
        api.groups.get_controllers.return_value = []
        result = json.loads(main.group_info(GROUP_ID, info_type="controllers"))
        assert result["info_type"] == "controllers"

    @patch("main.bloodhound_api")
    def test_dcom_rights(self, api):
        api.groups.get_dcom_rights.return_value = []
        result = json.loads(main.group_info(GROUP_ID, info_type="dcom_rights"))
        assert result["info_type"] == "dcom_rights"

    @patch("main.bloodhound_api")
    def test_members(self, api):
        api.groups.get_members.return_value = [{"name": "JDOE@CORP.LOCAL"}]
        result = json.loads(main.group_info(GROUP_ID, info_type="members"))
        assert result["info_type"] == "members"
        assert len(result["data"]) == 1

    @patch("main.bloodhound_api")
    def test_memberships(self, api):
        api.groups.get_memberships.return_value = []
        result = json.loads(main.group_info(GROUP_ID, info_type="memberships"))
        assert result["info_type"] == "memberships"

    @patch("main.bloodhound_api")
    def test_ps_remote_rights(self, api):
        api.groups.get_ps_remote_rights.return_value = []
        result = json.loads(main.group_info(GROUP_ID, info_type="ps_remote_rights"))
        assert result["info_type"] == "ps_remote_rights"

    @patch("main.bloodhound_api")
    def test_rdp_rights(self, api):
        api.groups.get_rdp_rights.return_value = []
        result = json.loads(main.group_info(GROUP_ID, info_type="rdp_rights"))
        assert result["info_type"] == "rdp_rights"

    @patch("main.bloodhound_api")
    def test_sessions(self, api):
        api.groups.get_sessions.return_value = []
        result = json.loads(main.group_info(GROUP_ID, info_type="sessions"))
        assert result["info_type"] == "sessions"

    def test_unknown_info_type(self):
        result = json.loads(main.group_info(GROUP_ID, info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# computer_info
# ---------------------------------------------------------------------------


class TestComputerInfo:
    @patch("main.bloodhound_api")
    def test_info(self, api):
        api.computers.get_info.return_value = {"name": "DC01.CORP.LOCAL"}
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="info"))
        assert result["info_type"] == "info"
        assert result["computer_id"] == COMPUTER_ID

    @patch("main.bloodhound_api")
    def test_admin_rights(self, api):
        api.computers.get_admin_rights.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="admin_rights"))
        assert result["info_type"] == "admin_rights"

    @patch("main.bloodhound_api")
    def test_admin_users(self, api):
        api.computers.get_admin_users.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="admin_users"))
        assert result["info_type"] == "admin_users"

    @patch("main.bloodhound_api")
    def test_constrained_delegation(self, api):
        api.computers.get_constrained_delegation_rights.return_value = []
        result = json.loads(
            main.computer_info(COMPUTER_ID, info_type="constrained_delegation")
        )
        assert result["info_type"] == "constrained_delegation"

    @patch("main.bloodhound_api")
    def test_constrained_users(self, api):
        api.computers.get_constrained_users.return_value = []
        result = json.loads(
            main.computer_info(COMPUTER_ID, info_type="constrained_users")
        )
        assert result["info_type"] == "constrained_users"

    @patch("main.bloodhound_api")
    def test_controllables(self, api):
        api.computers.get_controllables.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="controllables"))
        assert result["info_type"] == "controllables"

    @patch("main.bloodhound_api")
    def test_controllers(self, api):
        api.computers.get_controllers.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="controllers"))
        assert result["info_type"] == "controllers"

    @patch("main.bloodhound_api")
    def test_dcom_rights(self, api):
        api.computers.get_dcom_rights.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="dcom_rights"))
        assert result["info_type"] == "dcom_rights"

    @patch("main.bloodhound_api")
    def test_dcom_users(self, api):
        api.computers.get_dcom_users.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="dcom_users"))
        assert result["info_type"] == "dcom_users"

    @patch("main.bloodhound_api")
    def test_group_membership(self, api):
        api.computers.get_group_membership.return_value = []
        result = json.loads(
            main.computer_info(COMPUTER_ID, info_type="group_membership")
        )
        assert result["info_type"] == "group_membership"

    @patch("main.bloodhound_api")
    def test_ps_remote_rights(self, api):
        api.computers.get_ps_remote_rights.return_value = []
        result = json.loads(
            main.computer_info(COMPUTER_ID, info_type="ps_remote_rights")
        )
        assert result["info_type"] == "ps_remote_rights"

    @patch("main.bloodhound_api")
    def test_ps_remote_users(self, api):
        api.computers.get_ps_remote_users.return_value = []
        result = json.loads(
            main.computer_info(COMPUTER_ID, info_type="ps_remote_users")
        )
        assert result["info_type"] == "ps_remote_users"

    @patch("main.bloodhound_api")
    def test_rdp_rights(self, api):
        api.computers.get_rdp_rights.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="rdp_rights"))
        assert result["info_type"] == "rdp_rights"

    @patch("main.bloodhound_api")
    def test_rdp_users(self, api):
        api.computers.get_rdp_users.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="rdp_users"))
        assert result["info_type"] == "rdp_users"

    @patch("main.bloodhound_api")
    def test_sessions(self, api):
        api.computers.get_sessions.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="sessions"))
        assert result["info_type"] == "sessions"

    @patch("main.bloodhound_api")
    def test_sql_admins(self, api):
        api.computers.get_sql_admins.return_value = []
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="sql_admins"))
        assert result["info_type"] == "sql_admins"

    def test_unknown_info_type(self):
        result = json.loads(main.computer_info(COMPUTER_ID, info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# ou_info
# ---------------------------------------------------------------------------


class TestOuInfo:
    @patch("main.bloodhound_api")
    def test_info(self, api):
        api.ous.get_info.return_value = {"name": "IT"}
        result = json.loads(main.ou_info(OU_ID, info_type="info"))
        assert result["info_type"] == "info"
        assert result["ou_id"] == OU_ID

    @patch("main.bloodhound_api")
    def test_computers(self, api):
        api.ous.get_computers.return_value = []
        result = json.loads(main.ou_info(OU_ID, info_type="computers"))
        assert result["info_type"] == "computers"

    @patch("main.bloodhound_api")
    def test_groups(self, api):
        api.ous.get_groups.return_value = []
        result = json.loads(main.ou_info(OU_ID, info_type="groups"))
        assert result["info_type"] == "groups"

    @patch("main.bloodhound_api")
    def test_gpos(self, api):
        api.ous.get_gpos.return_value = []
        result = json.loads(main.ou_info(OU_ID, info_type="gpos"))
        assert result["info_type"] == "gpos"

    @patch("main.bloodhound_api")
    def test_users(self, api):
        api.ous.get_users.return_value = []
        result = json.loads(main.ou_info(OU_ID, info_type="users"))
        assert result["info_type"] == "users"

    def test_unknown_info_type(self):
        result = json.loads(main.ou_info(OU_ID, info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# gpo_info
# ---------------------------------------------------------------------------


class TestGpoInfo:
    @patch("main.bloodhound_api")
    def test_info(self, api):
        api.gpos.get_info.return_value = {"name": "Default Domain Policy"}
        result = json.loads(main.gpo_info(GPO_ID, info_type="info"))
        assert result["info_type"] == "info"
        assert result["gpo_id"] == GPO_ID

    @patch("main.bloodhound_api")
    def test_computers(self, api):
        api.gpos.get_computers.return_value = []
        result = json.loads(main.gpo_info(GPO_ID, info_type="computers"))
        assert result["info_type"] == "computers"

    @patch("main.bloodhound_api")
    def test_controllers(self, api):
        api.gpos.get_controllers.return_value = []
        result = json.loads(main.gpo_info(GPO_ID, info_type="controllers"))
        assert result["info_type"] == "controllers"

    @patch("main.bloodhound_api")
    def test_ous(self, api):
        api.gpos.get_ous.return_value = []
        result = json.loads(main.gpo_info(GPO_ID, info_type="ous"))
        assert result["info_type"] == "ous"

    @patch("main.bloodhound_api")
    def test_tier_zeros(self, api):
        api.gpos.get_tier_zeros.return_value = []
        result = json.loads(main.gpo_info(GPO_ID, info_type="tier_zeros"))
        assert result["info_type"] == "tier_zeros"

    @patch("main.bloodhound_api")
    def test_users(self, api):
        api.gpos.get_users.return_value = []
        result = json.loads(main.gpo_info(GPO_ID, info_type="users"))
        assert result["info_type"] == "users"

    def test_unknown_info_type(self):
        result = json.loads(main.gpo_info(GPO_ID, info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# graph_analysis
# ---------------------------------------------------------------------------


class TestGraphAnalysis:
    @patch("main.bloodhound_api")
    def test_search(self, api):
        api.graph.search.return_value = [{"name": "DC01"}]
        result = json.loads(
            main.graph_analysis(info_type="search", query="DC01", search_type="fuzzy")
        )
        assert result["info_type"] == "search"
        api.graph.search.assert_called_once_with("DC01", "fuzzy")

    @patch("main.bloodhound_api")
    def test_shortest_path(self, api):
        api.graph.get_shortest_path.return_value = {"path": []}
        result = json.loads(
            main.graph_analysis(
                info_type="shortest_path",
                start_node=USER_ID,
                end_node=GROUP_ID,
            )
        )
        assert result["info_type"] == "shortest_path"
        api.graph.get_shortest_path.assert_called_once_with(USER_ID, GROUP_ID, None)

    @patch("main.bloodhound_api")
    def test_shortest_path_with_relationship_kinds(self, api):
        api.graph.get_shortest_path.return_value = {"path": []}
        main.graph_analysis(
            info_type="shortest_path",
            start_node=USER_ID,
            end_node=GROUP_ID,
            relationship_kinds="MemberOf,AdminTo",
        )
        api.graph.get_shortest_path.assert_called_once_with(
            USER_ID, GROUP_ID, "MemberOf,AdminTo"
        )

    @patch("main.bloodhound_api")
    def test_edge_composition(self, api):
        api.graph.get_edge_composition.return_value = {"edges": []}
        result = json.loads(
            main.graph_analysis(
                info_type="edge_composition",
                source_node=USER_ID,
                target_node=COMPUTER_ID,
                edge_type="GenericAll",
            )
        )
        assert result["info_type"] == "edge_composition"
        api.graph.get_edge_composition.assert_called_once_with(
            USER_ID, COMPUTER_ID, "GenericAll"
        )

    @patch("main.bloodhound_api")
    def test_relay_targets(self, api):
        api.graph.get_relay_targets.return_value = []
        result = json.loads(
            main.graph_analysis(
                info_type="relay_targets",
                source_node=USER_ID,
                target_node=COMPUTER_ID,
                edge_type="CoerceAndRelayNTLMToSMB",
            )
        )
        assert result["info_type"] == "relay_targets"

    def test_unknown_info_type(self):
        result = json.loads(main.graph_analysis(info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# adcs_info
# ---------------------------------------------------------------------------


class TestAdcsInfo:
    @patch("main.bloodhound_api")
    def test_cert_template_info(self, api):
        api.adcs.get_cert_template_info.return_value = {"name": "UserTemplate"}
        result = json.loads(
            main.adcs_info(TEMPLATE_ID, info_type="cert_template_info")
        )
        assert result["info_type"] == "cert_template_info"
        assert result["object_id"] == TEMPLATE_ID

    @patch("main.bloodhound_api")
    def test_cert_template_controllers(self, api):
        api.adcs.get_cert_template_controllers.return_value = []
        result = json.loads(
            main.adcs_info(TEMPLATE_ID, info_type="cert_template_controllers")
        )
        assert result["info_type"] == "cert_template_controllers"

    @patch("main.bloodhound_api")
    def test_root_ca_info(self, api):
        api.adcs.get_root_ca_info.return_value = {"name": "CORP-ROOT-CA"}
        result = json.loads(main.adcs_info(CA_ID, info_type="root_ca_info"))
        assert result["info_type"] == "root_ca_info"

    @patch("main.bloodhound_api")
    def test_root_ca_controllers(self, api):
        api.adcs.get_root_ca_controllers.return_value = []
        result = json.loads(main.adcs_info(CA_ID, info_type="root_ca_controllers"))
        assert result["info_type"] == "root_ca_controllers"

    @patch("main.bloodhound_api")
    def test_enterprise_ca_info(self, api):
        api.adcs.get_enterprise_ca_info.return_value = {"name": "CORP-ENT-CA"}
        result = json.loads(main.adcs_info(CA_ID, info_type="enterprise_ca_info"))
        assert result["info_type"] == "enterprise_ca_info"

    @patch("main.bloodhound_api")
    def test_enterprise_ca_controllers(self, api):
        api.adcs.get_enterprise_ca_controllers.return_value = []
        result = json.loads(
            main.adcs_info(CA_ID, info_type="enterprise_ca_controllers")
        )
        assert result["info_type"] == "enterprise_ca_controllers"

    @patch("main.bloodhound_api")
    def test_aia_ca_controllers(self, api):
        api.adcs.get_aia_ca_controllers.return_value = []
        result = json.loads(main.adcs_info(CA_ID, info_type="aia_ca_controllers"))
        assert result["info_type"] == "aia_ca_controllers"

    def test_unknown_info_type(self):
        result = json.loads(main.adcs_info(CA_ID, info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# cypher_query
# ---------------------------------------------------------------------------


class TestCypherQuery:
    @patch("main.bloodhound_api")
    def test_run_success_with_nodes(self, api):
        api.cypher.run_query.return_value = {
            "nodes": {"n1": {"objectid": "S-1-5", "label": "User"}},
            "edges": [],
        }
        result = json.loads(
            main.cypher_query(
                info_type="run",
                query="MATCH (n:User) RETURN n LIMIT 1",
            )
        )
        assert result["info_type"] == "run"
        assert result["success"] is True
        assert result["node_count"] == 1
        assert result["edge_count"] == 0

    @patch("main.bloodhound_api")
    def test_run_success_empty_results(self, api):
        api.cypher.run_query.return_value = {"nodes": {}, "edges": []}
        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n:User) RETURN n")
        )
        assert result["success"] is True
        assert result["node_count"] == 0

    @patch("main.bloodhound_api")
    def test_run_syntax_error(self, api):
        api.cypher.run_query.side_effect = make_api_error(400)
        result = json.loads(main.cypher_query(info_type="run", query="MATCH garbage"))
        assert result["success"] is False
        assert result["error_type"] == "syntax_error"
        assert result["http_status"] == 400
        assert "hint" in result

    @patch("main.bloodhound_api")
    def test_run_auth_error(self, api):
        api.cypher.run_query.side_effect = make_api_error(401)
        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )
        assert result["success"] is False
        assert result["error_type"] == "auth_error"
        assert result["http_status"] == 401

    @patch("main.bloodhound_api")
    def test_run_permission_error(self, api):
        api.cypher.run_query.side_effect = make_api_error(403)
        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )
        assert result["success"] is False
        assert result["error_type"] == "permission_error"
        assert result["http_status"] == 403

    @patch("main.bloodhound_api")
    def test_run_not_found(self, api):
        api.cypher.run_query.side_effect = make_api_error(404)
        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )
        assert result["success"] is False
        assert result["error_type"] == "not_found"
        assert result["http_status"] == 404

    @patch("main.bloodhound_api")
    def test_run_server_error(self, api):
        api.cypher.run_query.side_effect = make_api_error(500)
        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )
        assert result["success"] is False
        assert result["error_type"] == "server_error"
        assert result["http_status"] == 500

    @patch("main.bloodhound_api")
    def test_run_server_error_above_500(self, api):
        api.cypher.run_query.side_effect = make_api_error(503)
        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )
        assert result["success"] is False
        assert result["error_type"] == "server_error"
        assert result["http_status"] == 503

    @patch("main.bloodhound_api")
    def test_run_rate_limit_error(self, api):
        api.cypher.run_query.side_effect = make_api_error(429)
        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )
        assert result["success"] is False
        assert result["error_type"] == "rate_limit"
        assert result["http_status"] == 429

    @patch("main.bloodhound_api")
    def test_run_uses_response_status_when_error_status_is_none(self, api):
        body = {
            "error": (
                "Neo4jError: Neo.ClientError.Statement.SyntaxError "
                "(Multiple result columns with the same name are not supported)"
            ),
            "request_id": "req-123",
        }
        api.cypher.run_query.side_effect = make_api_error_with_body(
            None,
            body=body,
            response_status_code=500,
        )

        result = json.loads(
            main.cypher_query(
                info_type="run",
                query=(
                    "MATCH (u:User) RETURN u.name, "
                    "u.serviceprincipalnames, u.serviceprincipalnames"
                ),
            )
        )

        assert result["success"] is False
        assert result["error_type"] == "syntax_error"
        assert result["http_status"] == 500
        assert result["request_id"] == "req-123"
        assert "Multiple result columns" in result["error"]
        assert "duplicate RETURN column names" in result["hint"]

    @patch("main.bloodhound_api")
    def test_run_missing_status_and_response_returns_api_error(self, api):
        api.cypher.run_query.side_effect = make_api_error_with_body(None)

        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )

        assert result["success"] is False
        assert result["error_type"] == "api_error"
        assert result["http_status"] is None
        assert "hint" in result

    @patch("main.bloodhound_api")
    def test_run_500_neo4j_client_error_classified_as_query_error(self, api):
        api.cypher.run_query.side_effect = make_api_error_with_body(
            500,
            body="Neo4jError: Neo.ClientError.Statement.TypeError invalid expression",
        )

        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )

        assert result["success"] is False
        assert result["error_type"] == "query_error"
        assert result["http_status"] == 500

    @patch("main.bloodhound_api")
    def test_run_metadata_enriched_response(self, api):
        api.cypher.run_query.return_value = {
            "metadata": {"has_result": True},
            "data": {"nodes": {"n1": {}}, "edges": []},
        }
        result = json.loads(
            main.cypher_query(info_type="run", query="MATCH (n) RETURN n")
        )
        assert result["success"] is True
        assert result["has_results"] is True

    @patch("main.bloodhound_api")
    def test_run_count_query_marks_gui_incompatible(self, api):
        api.cypher.run_query.return_value = {
            "metadata": {"has_results": True},
            "data": {"columns": ["total"], "rows": [{"total": 42}]},
        }
        result = json.loads(
            main.cypher_query(
                info_type="run",
                query="MATCH (n) RETURN count(n) AS total",
            )
        )

        assert result["success"] is True
        assert result["query_compatibility"]["api_safe"] is True
        assert result["query_compatibility"]["gui_safe"] is False
        assert result["query_compatibility"]["aggregation_functions"] == ["COUNT"]
        assert "COUNT" in result["query_compatibility"]["gui_safe_guidance"]

    def test_interpret_failed_query(self):
        failed = json.dumps({"success": False, "error": "syntax error"})
        result = json.loads(
            main.cypher_query(
                info_type="interpret",
                query="MATCH garbage",
                result_json=failed,
            )
        )
        assert result["info_type"] == "interpret"
        assert "error" in result["interpretation"].lower()

    def test_interpret_successful_query(self):
        success = json.dumps(
            {
                "success": True,
                "data": {
                    "nodes": {"n1": {}, "n2": {}},
                    "edges": [{"id": "e1"}],
                },
            }
        )
        result = json.loads(
            main.cypher_query(
                info_type="interpret",
                query="MATCH (n) RETURN n",
                result_json=success,
            )
        )
        assert result["info_type"] == "interpret"
        assert result["nodes_found"] == 2
        assert result["edges_found"] == 1
        assert result["has_results"] is True

    @patch("main.bloodhound_api")
    def test_list_saved(self, api):
        api.cypher.list_saved_queries.return_value = []
        result = json.loads(main.cypher_query(info_type="list_saved"))
        assert result["info_type"] == "list_saved"

    @patch("main.bloodhound_api")
    def test_create_saved(self, api):
        api.cypher.create_saved_query.return_value = {"id": QUERY_ID}
        result = json.loads(
            main.cypher_query(
                info_type="create_saved",
                name="DA Members",
                query="MATCH (n)-[:MemberOf]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}) RETURN n",
            )
        )
        assert result["info_type"] == "create_saved"
        api.cypher.create_saved_query.assert_called_once()

    @patch("main.bloodhound_api")
    def test_get_saved(self, api):
        api.cypher.get_saved_query.return_value = {"id": QUERY_ID, "name": "DA"}
        result = json.loads(
            main.cypher_query(info_type="get_saved", query_id=QUERY_ID)
        )
        assert result["info_type"] == "get_saved"

    @patch("main.bloodhound_api")
    def test_update_saved(self, api):
        api.cypher.update_saved_query.return_value = {"id": QUERY_ID}
        result = json.loads(
            main.cypher_query(
                info_type="update_saved",
                query_id=QUERY_ID,
                name="DA Members Updated",
            )
        )
        assert result["info_type"] == "update_saved"

    @patch("main.bloodhound_api")
    def test_delete_saved(self, api):
        api.cypher.delete_saved_query.return_value = None
        result = json.loads(
            main.cypher_query(info_type="delete_saved", query_id=QUERY_ID)
        )
        assert result["info_type"] == "delete_saved"

    @patch("main.bloodhound_api")
    def test_share_saved_with_user_ids(self, api):
        api.cypher.share_saved_query.return_value = None
        main.cypher_query(
            info_type="share_saved",
            query_id=QUERY_ID,
            user_ids="1,2,3",
            public=False,
        )
        api.cypher.share_saved_query.assert_called_once_with(QUERY_ID, [1, 2, 3], False)

    @patch("main.bloodhound_api")
    def test_share_saved_public(self, api):
        api.cypher.share_saved_query.return_value = None
        main.cypher_query(info_type="share_saved", query_id=QUERY_ID, public=True)
        api.cypher.share_saved_query.assert_called_once_with(QUERY_ID, [], True)

    @patch("main.bloodhound_api")
    def test_validate(self, api):
        api.cypher.validate_query.return_value = {"valid": True}
        result = json.loads(
            main.cypher_query(
                info_type="validate",
                query="MATCH (n:User) RETURN n",
            )
        )
        assert result["info_type"] == "validate"

    def test_unknown_info_type(self):
        result = json.loads(main.cypher_query(info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# data_quality
# ---------------------------------------------------------------------------


class TestDataQuality:
    @patch("main.bloodhound_api")
    def test_completeness(self, api):
        api.data_quality.get_completeness_stats.return_value = {"score": 95}
        result = json.loads(main.data_quality(info_type="completeness"))
        assert result["info_type"] == "completeness"
        api.data_quality.get_completeness_stats.assert_called_once()

    @patch("main.bloodhound_api")
    def test_ad_domain(self, api):
        api.data_quality.get_ad_domain_data_quality_stats.return_value = []
        result = json.loads(
            main.data_quality(info_type="ad_domain", domain_id=DOMAIN_ID)
        )
        assert result["info_type"] == "ad_domain"
        api.data_quality.get_ad_domain_data_quality_stats.assert_called_once_with(
            DOMAIN_ID, None, None, None, 0, 100
        )

    @patch("main.bloodhound_api")
    def test_azure_tenant(self, api):
        api.data_quality.get_azure_tenant_data_quality_stats.return_value = []
        result = json.loads(
            main.data_quality(info_type="azure_tenant", tenant_id="TENANT-123")
        )
        assert result["info_type"] == "azure_tenant"

    @patch("main.bloodhound_api")
    def test_platform(self, api):
        api.data_quality.get_platform_data_quality_stats.return_value = []
        result = json.loads(main.data_quality(info_type="platform", platform_id="ad"))
        assert result["info_type"] == "platform"

    def test_unknown_info_type(self):
        result = json.loads(main.data_quality(info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# custom_nodes
# ---------------------------------------------------------------------------


class TestCustomNodes:
    @patch("main.bloodhound_api")
    def test_list(self, api):
        api.custom_nodes.get_all_custom_nodes.return_value = []
        result = json.loads(main.custom_nodes(info_type="list"))
        assert result["info_type"] == "list"
        api.custom_nodes.get_all_custom_nodes.assert_called_once()

    @patch("main.bloodhound_api")
    def test_get(self, api):
        api.custom_nodes.get_custom_node.return_value = {"kind": "SQLServer"}
        result = json.loads(main.custom_nodes(info_type="get", kind_name="SQLServer"))
        assert result["info_type"] == "get"
        api.custom_nodes.get_custom_node.assert_called_once_with("SQLServer")

    @patch("main.bloodhound_api")
    def test_create_without_icon(self, api):
        api.custom_nodes.create_custom_nodes.return_value = {"created": True}
        types_json = json.dumps({"SQLServer": {"color": "#ff0000"}})
        result = json.loads(
            main.custom_nodes(info_type="create", custom_types_json=types_json)
        )
        assert result["info_type"] == "create"
        api.custom_nodes.create_custom_nodes.assert_called_once()

    @patch("main.bloodhound_api")
    def test_create_with_valid_icon(self, api):
        api.custom_nodes.validate_icon_config.return_value = {"valid": True}
        api.custom_nodes.create_custom_nodes.return_value = {"created": True}
        types_json = json.dumps({"SQLServer": {"icon": {"type": "font-awesome"}}})
        result = json.loads(
            main.custom_nodes(info_type="create", custom_types_json=types_json)
        )
        assert result["info_type"] == "create"

    @patch("main.bloodhound_api")
    def test_create_accepts_coerced_object_payload(self, api):
        api.custom_nodes.validate_icon_config.return_value = {"valid": True}
        api.custom_nodes.create_custom_nodes.return_value = {"created": True}
        payload = {
            "GH_User": {
                "icon": {
                    "type": "font-awesome",
                    "name": "user",
                    "color": "#FF8E40",
                }
            }
        }

        result = json.loads(
            main.custom_nodes(info_type="create", custom_types_json=payload)
        )

        assert result["info_type"] == "create"
        api.custom_nodes.validate_icon_config.assert_called_once_with(
            payload["GH_User"]["icon"]
        )
        api.custom_nodes.create_custom_nodes.assert_called_once_with(payload)

    @patch("main.bloodhound_api")
    def test_create_accepts_native_custom_types_payload(self, api):
        api.custom_nodes.validate_icon_config.return_value = {"valid": True}
        api.custom_nodes.create_custom_nodes.return_value = {"created": True}
        payload = {
            "custom_types": {
                "GH_User": {
                    "icon": {
                        "type": "font-awesome",
                        "name": "user",
                        "color": "#FF8E40",
                    }
                }
            }
        }

        result = json.loads(
            main.custom_nodes(info_type="create", custom_types_json=payload)
        )

        assert result["info_type"] == "create"
        api.custom_nodes.validate_icon_config.assert_called_once_with(
            payload["custom_types"]["GH_User"]["icon"]
        )
        api.custom_nodes.create_custom_nodes.assert_called_once_with(payload)

    @patch("main.bloodhound_api")
    def test_create_with_invalid_icon_returns_error(self, api):
        api.custom_nodes.validate_icon_config.return_value = {
            "valid": False,
            "error": "bad icon",
        }
        types_json = json.dumps({"SQLServer": {"icon": {"type": "bad"}}})
        result = json.loads(
            main.custom_nodes(info_type="create", custom_types_json=types_json)
        )
        assert result["info_type"] == "create"
        assert "error" in result["data"]

    @patch("main.bloodhound_api")
    def test_delete(self, api):
        api.custom_nodes.delete_custom_node.return_value = None
        result = json.loads(
            main.custom_nodes(info_type="delete", kind_name="SQLServer")
        )
        assert result["info_type"] == "delete"
        api.custom_nodes.delete_custom_node.assert_called_once_with("SQLServer")

    @patch("main.bloodhound_api")
    def test_validate_icon(self, api):
        api.custom_nodes.validate_icon_config.return_value = {"valid": True}
        result = json.loads(
            main.custom_nodes(
                info_type="validate_icon",
                icon_config_json=json.dumps({"type": "font-awesome", "name": "server"}),
            )
        )
        assert result["info_type"] == "validate_icon"

    @patch("main.bloodhound_api")
    def test_validate_icon_accepts_coerced_object_payload(self, api):
        api.custom_nodes.validate_icon_config.return_value = {"valid": True}
        icon = {"type": "font-awesome", "name": "user", "color": "#FF8E40"}

        result = json.loads(
            main.custom_nodes(info_type="validate_icon", icon_config_json=icon)
        )

        assert result["info_type"] == "validate_icon"
        api.custom_nodes.validate_icon_config.assert_called_once_with(icon)

    @patch("main.bloodhound_api")
    def test_validate_icon_accepts_double_encoded_json_string(self, api):
        api.custom_nodes.validate_icon_config.return_value = {"valid": True}
        icon = {"type": "font-awesome", "name": "user", "color": "#FF8E40"}

        result = json.loads(
            main.custom_nodes(
                info_type="validate_icon",
                icon_config_json=json.dumps(json.dumps(icon)),
            )
        )

        assert result["info_type"] == "validate_icon"
        api.custom_nodes.validate_icon_config.assert_called_once_with(icon)

    @patch("main.bloodhound_api")
    def test_extension_list(self, api):
        api.opengraph_extensions.list_extensions.return_value = {
            "data": {"extensions": []}
        }

        result = json.loads(main.custom_nodes(info_type="extension_list"))

        assert result["info_type"] == "extension_list"
        assert result["data"] == {"data": {"extensions": []}}
        api.opengraph_extensions.list_extensions.assert_called_once()

    @patch("main.bloodhound_api")
    def test_extension_upsert_accepts_object_payload(self, api):
        payload = {"schema": {"name": "GitHub"}, "node_kinds": []}
        api.opengraph_extensions.upsert_extension.return_value = {"data": {"id": 3}}

        result = json.loads(
            main.custom_nodes(info_type="extension_upsert", extension_json=payload)
        )

        assert result["info_type"] == "extension_upsert"
        assert result["data"]["source"] == {"type": "argument"}
        assert result["data"]["result"] == {"data": {"id": 3}}
        api.opengraph_extensions.upsert_extension.assert_called_once_with(payload)

    @patch("main.bloodhound_api")
    def test_extension_upsert_accepts_json_string(self, api):
        payload = {"schema": {"name": "GitHub"}, "node_kinds": []}
        api.opengraph_extensions.upsert_extension.return_value = {"data": {"id": 3}}

        result = json.loads(
            main.custom_nodes(
                info_type="extension_upsert",
                extension_json=json.dumps(payload),
            )
        )

        assert result["info_type"] == "extension_upsert"
        api.opengraph_extensions.upsert_extension.assert_called_once_with(payload)

    @patch("main.bloodhound_api")
    def test_extension_upsert_accepts_file_path(self, api, tmp_path):
        payload = {"schema": {"name": "GitHub"}, "node_kinds": []}
        extension_file = tmp_path / "github-extension.json"
        extension_file.write_text(json.dumps(payload))
        api.opengraph_extensions.upsert_extension.return_value = {"data": {"id": 3}}

        result = json.loads(
            main.custom_nodes(
                info_type="extension_upsert",
                extension_file_path=str(extension_file),
            )
        )

        assert result["info_type"] == "extension_upsert"
        assert result["data"]["source"]["type"] == "file"
        assert result["data"]["source"]["file_name"] == "github-extension.json"
        api.opengraph_extensions.upsert_extension.assert_called_once_with(payload)

    @patch("main.bloodhound_api")
    def test_extension_upsert_rejects_non_json_file_path(self, api, tmp_path):
        extension_file = tmp_path / "github-extension.txt"
        extension_file.write_text("{}")

        result = json.loads(
            main.custom_nodes(
                info_type="extension_upsert",
                extension_file_path=str(extension_file),
            )
        )

        assert "error" in result
        assert "Extension file must be JSON" in result["error"]
        api.opengraph_extensions.upsert_extension.assert_not_called()

    @patch("main.bloodhound_api")
    def test_extension_upsert_returns_feature_unavailable_on_404(self, api):
        api.opengraph_extensions.upsert_extension.side_effect = make_api_error(404)

        result = json.loads(
            main.custom_nodes(
                info_type="extension_upsert",
                extension_json={"schema": {"name": "GitHub"}},
            )
        )

        assert result["info_type"] == "extension_upsert"
        assert result["data"]["status"] == "feature_unavailable"
        assert result["data"]["endpoint"] == "/api/v2/extensions"
        assert "fallback_hint" in result["data"]

    @patch("main.bloodhound_api")
    def test_extension_delete(self, api):
        api.opengraph_extensions.delete_extension.return_value = None

        result = json.loads(
            main.custom_nodes(info_type="extension_delete", extension_id=7)
        )

        assert result["info_type"] == "extension_delete"
        assert result["data"] == {"status": "deleted", "extension_id": 7}
        api.opengraph_extensions.delete_extension.assert_called_once_with(7)

    @patch("main.bloodhound_api")
    def test_extension_edges_filters(self, api):
        api.opengraph_extensions.list_edge_kinds.return_value = {"data": []}

        result = json.loads(
            main.custom_nodes(
                info_type="extension_edges",
                schemas=["GitHub", "Okta"],
                is_traversable=True,
            )
        )

        assert result["info_type"] == "extension_edges"
        api.opengraph_extensions.list_edge_kinds.assert_called_once_with(
            schemas=["GitHub", "Okta"],
            is_traversable="eq:true",
        )

    @patch("main.bloodhound_api")
    def test_extension_edges_accepts_json_schema_filter(self, api):
        api.opengraph_extensions.list_edge_kinds.return_value = {"data": []}

        result = json.loads(
            main.custom_nodes(
                info_type="extension_edges",
                schemas=json.dumps(["GitHub"]),
                is_traversable="neq:false",
            )
        )

        assert result["info_type"] == "extension_edges"
        api.opengraph_extensions.list_edge_kinds.assert_called_once_with(
            schemas=["GitHub"],
            is_traversable="neq:false",
        )

    def test_unknown_info_type(self):
        result = json.loads(main.custom_nodes(info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# asset_groups
# ---------------------------------------------------------------------------


class TestAssetGroups:
    @patch("main.bloodhound_api")
    def test_list(self, api):
        api.asset_groups.list_asset_groups.return_value = []
        result = json.loads(main.asset_groups(info_type="list"))
        assert result["info_type"] == "list"

    @patch("main.bloodhound_api")
    def test_get(self, api):
        api.asset_groups.get_asset_group.return_value = {"id": "1", "name": "Tier Zero"}
        result = json.loads(main.asset_groups(info_type="get", asset_group_id="1"))
        assert result["info_type"] == "get"
        api.asset_groups.get_asset_group.assert_called_once_with("1")

    @patch("main.bloodhound_api")
    def test_create(self, api):
        api.asset_groups.create_asset_group.return_value = {"id": "2"}
        result = json.loads(
            main.asset_groups(info_type="create", name="High Value", tag="high_value")
        )
        assert result["info_type"] == "create"
        api.asset_groups.create_asset_group.assert_called_once_with(
            "High Value", "high_value"
        )

    @patch("main.bloodhound_api")
    def test_update(self, api):
        api.asset_groups.update_asset_group.return_value = {"id": "1"}
        result = json.loads(
            main.asset_groups(
                info_type="update", asset_group_id="1", name="Tier Zero Updated"
            )
        )
        assert result["info_type"] == "update"

    @patch("main.bloodhound_api")
    def test_delete(self, api):
        api.asset_groups.delete_asset_group.return_value = None
        result = json.loads(
            main.asset_groups(info_type="delete", asset_group_id="1")
        )
        assert result["info_type"] == "delete"

    @patch("main.bloodhound_api")
    def test_collections(self, api):
        api.asset_groups.list_asset_group_collections.return_value = []
        result = json.loads(
            main.asset_groups(info_type="collections", asset_group_id="1")
        )
        assert result["info_type"] == "collections"

    @patch("main.bloodhound_api")
    def test_member_counts(self, api):
        api.asset_groups.list_asset_group_member_counts.return_value = {}
        result = json.loads(
            main.asset_groups(info_type="member_counts", asset_group_id="1")
        )
        assert result["info_type"] == "member_counts"

    @patch("main.bloodhound_api")
    def test_update_selectors(self, api):
        api.asset_groups.update_asset_group_selectors.return_value = {}
        selectors = json.dumps([{"selector_name": "S-1-5-21-*", "sid": "S-1-5-21-*"}])
        result = json.loads(
            main.asset_groups(
                info_type="update_selectors",
                asset_group_id="1",
                selectors_json=selectors,
            )
        )
        assert result["info_type"] == "update_selectors"

    @patch("main.bloodhound_api")
    def test_list_tags(self, api):
        api.asset_groups.list_asset_group_tags.return_value = []
        result = json.loads(main.asset_groups(info_type="list_tags"))
        assert result["info_type"] == "list_tags"

    @patch("main.bloodhound_api")
    def test_create_tag(self, api):
        api.asset_groups.create_asset_group_tag.return_value = {"id": "5"}
        result = json.loads(
            main.asset_groups(
                info_type="create_tag", name="Sensitive", tag="sensitive"
            )
        )
        assert result["info_type"] == "create_tag"

    @patch("main.bloodhound_api")
    def test_tag_members(self, api):
        api.asset_groups.list_asset_group_tag_members.return_value = []
        result = json.loads(
            main.asset_groups(info_type="tag_members", asset_group_tag_id=5)
        )
        assert result["info_type"] == "tag_members"

    def test_unknown_info_type(self):
        result = json.loads(main.asset_groups(info_type="bad"))
        assert "error" in result


# ---------------------------------------------------------------------------
# Response format contract
# ---------------------------------------------------------------------------


class TestResponseFormat:
    """Verify all tools return valid JSON strings with consistent structure."""

    @patch("main.bloodhound_api")
    def test_success_response_has_info_type_and_data(self, api):
        api.domains.get_all.return_value = []
        raw = main.domain_info(info_type="list")
        parsed = json.loads(raw)
        assert "info_type" in parsed
        assert "data" in parsed

    @patch("main.bloodhound_api")
    def test_error_response_has_error_key(self, api):
        api.domains.get_all.side_effect = BloodhoundConnectionError("down")
        raw = main.domain_info(info_type="list")
        parsed = json.loads(raw)
        assert "error" in parsed

    @patch("main.bloodhound_api")
    def test_all_tools_return_json_strings(self, api):
        """Every composite tool must return a JSON string, never a dict."""
        api.domains.get_all.return_value = []
        api.users.get_info.return_value = {}
        api.groups.get_info.return_value = {}
        api.computers.get_info.return_value = {}
        api.ous.get_info.return_value = {}
        api.gpos.get_info.return_value = {}
        api.graph.search.return_value = []
        api.adcs.get_cert_template_info.return_value = {}
        api.cypher.list_saved_queries.return_value = []
        api.data_quality.get_completeness_stats.return_value = {}
        api.custom_nodes.get_all_custom_nodes.return_value = []
        api.asset_groups.list_asset_groups.return_value = []

        calls = [
            main.domain_info(info_type="list"),
            main.user_info(USER_ID, info_type="info"),
            main.group_info(GROUP_ID, info_type="info"),
            main.computer_info(COMPUTER_ID, info_type="info"),
            main.ou_info(OU_ID, info_type="info"),
            main.gpo_info(GPO_ID, info_type="info"),
            main.graph_analysis(info_type="search", query="test"),
            main.adcs_info(TEMPLATE_ID, info_type="cert_template_info"),
            main.cypher_query(info_type="list_saved"),
            main.data_quality(info_type="completeness"),
            main.custom_nodes(info_type="list"),
            main.asset_groups(info_type="list"),
        ]
        for r in calls:
            assert isinstance(r, str), f"Tool returned {type(r)}, expected str"
            json.loads(r)  # must be valid JSON


class TestFileUpload:
    """Tests for file_upload composite tool"""

    def test_upload_dispatches_to_upload_collection_file(self, tmp_path):
        zip_file = tmp_path / "sharphound.zip"
        zip_file.write_bytes(b"PK\x03\x04fakezip")
        expected = {
            "job_id": 1,
            "file_name": "sharphound.zip",
            "file_size_bytes": 16,
            "content_type": "application/zip",
            "status": "upload_complete",
        }
        with patch("main.bloodhound_api") as mock_api:
            mock_api.file_upload.upload_collection_file.return_value = expected
            result = json.loads(main.file_upload(info_type="upload", file_path=str(zip_file)))
        assert result["data"] == expected
        mock_api.file_upload.upload_collection_file.assert_called_once_with(str(zip_file))

    def test_start_job_returns_job_id(self):
        with patch("main.bloodhound_api") as mock_api:
            mock_api.file_upload.start_upload.return_value = 42
            result = json.loads(main.file_upload(info_type="start_job"))
        assert result["data"]["job_id"] == 42

    def test_upload_to_job(self, tmp_path):
        json_file = tmp_path / "users.json"
        json_file.write_bytes(b'{"data":[]}')
        with patch("main.bloodhound_api") as mock_api:
            mock_api.file_upload._validate_file.return_value = None
            mock_api.file_upload.upload_file.return_value = None
            result = json.loads(
                main.file_upload(info_type="upload_to_job", job_id=7, file_path=str(json_file))
            )
        assert result["data"]["job_id"] == 7
        assert result["data"]["file_name"] == "users.json"
        assert result["data"]["status"] == "uploaded"

    def test_end_job(self):
        with patch("main.bloodhound_api") as mock_api:
            mock_api.file_upload.end_upload.return_value = None
            result = json.loads(main.file_upload(info_type="end_job", job_id=42))
        assert result["data"]["status"] == "ingest_started"
        assert result["data"]["job_id"] == 42
        mock_api.file_upload.end_upload.assert_called_once_with(42)

    def test_unknown_info_type(self):
        with patch("main.bloodhound_api"):
            result = json.loads(main.file_upload(info_type="nonexistent"))
        assert "error" in result
        assert "nonexistent" in result["error"]
        for valid in ("upload", "start_job", "upload_to_job", "end_job"):
            assert valid in result["error"]

    def test_api_error_propagation(self, tmp_path):
        zip_file = tmp_path / "test.zip"
        zip_file.write_bytes(b"data")
        with patch("main.bloodhound_api") as mock_api:
            mock_api.file_upload.upload_collection_file.side_effect = make_api_error(500)
            result = json.loads(main.file_upload(info_type="upload", file_path=str(zip_file)))
        assert "error" in result
        assert "500" in result["error"]

    def test_connection_error_propagation(self, tmp_path):
        zip_file = tmp_path / "test.zip"
        zip_file.write_bytes(b"data")
        with patch("main.bloodhound_api") as mock_api:
            mock_api.file_upload.upload_collection_file.side_effect = (
                BloodhoundConnectionError("connection refused")
            )
            result = json.loads(main.file_upload(info_type="upload", file_path=str(zip_file)))
        assert "error" in result
        assert "connection" in result["error"].lower()

    def test_file_upload_returns_valid_json(self, tmp_path):
        zip_file = tmp_path / "test.zip"
        zip_file.write_bytes(b"PK")
        with patch("main.bloodhound_api") as mock_api:
            mock_api.file_upload.upload_collection_file.return_value = {"status": "ok"}
            result = main.file_upload(info_type="upload", file_path=str(zip_file))
        assert isinstance(result, str)
        json.loads(result)
