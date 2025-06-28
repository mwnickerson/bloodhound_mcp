import json
import os
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# Add the project root to Python path so we can import main.py
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Import strategy: Import main normally, but we'll mock the bloodhound_api instance
try:
    import main
    MAIN_IMPORTED = True
    print("✅ Successfully imported main.py")
except Exception as e:
    MAIN_IMPORTED = False
    print(f"❌ Failed to import main.py: {e}")
    main = Mock()


class TestDomainMCPToolsComplete:
    """Comprehensive tests for all domain-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_groups(self, mock_api):
        """Test get_groups MCP tool"""
        fake_groups = {"data": [{"objectid": "group1", "name": "Domain Admins"}], "count": 1}
        mock_api.domains.get_groups.return_value = fake_groups
        
        result_json = main.get_groups("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_groups.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "groups" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computers(self, mock_api):
        """Test get_computers MCP tool"""
        fake_computers = {"data": [{"objectid": "comp1", "name": "DC01"}], "count": 1}
        mock_api.domains.get_computers.return_value = fake_computers
        
        result_json = main.get_computers("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_computers.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_security_controllers(self, mock_api):
        """Test get_security_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "Admin@domain.local"}], "count": 1}
        mock_api.domains.get_controllers.return_value = fake_controllers
        
        result_json = main.get_security_controllers("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_controllers.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_gpos(self, mock_api):
        """Test get_gpos MCP tool"""
        fake_gpos = {"data": [{"objectid": "gpo1", "name": "Default Domain Policy"}], "count": 1}
        mock_api.domains.get_gpos.return_value = fake_gpos
        
        result_json = main.get_gpos("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_gpos.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "gpos" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_ous(self, mock_api):
        """Test get_ous MCP tool"""
        fake_ous = {"data": [{"objectid": "ou1", "name": "Domain Controllers"}], "count": 1}
        mock_api.domains.get_ous.return_value = fake_ous
        
        result_json = main.get_ous("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_ous.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "ous" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_dc_syncers(self, mock_api):
        """Test get_dc_syncers MCP tool"""
        fake_syncers = {"data": [{"objectid": "sync1", "name": "SYNC01$"}], "count": 1}
        mock_api.domains.get_dc_syncers.return_value = fake_syncers
        
        result_json = main.get_dc_syncers("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_dc_syncers.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "dc_syncers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_foreign_admins(self, mock_api):
        """Test get_foreign_admins MCP tool"""
        fake_admins = {"data": [{"objectid": "admin1", "name": "FOREIGN\\Administrator"}], "count": 1}
        mock_api.domains.get_foreign_admins.return_value = fake_admins
        
        result_json = main.get_foreign_admins("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_foreign_admins.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "foreign_admins" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_foreign_gpo_controllers(self, mock_api):
        """Test get_foreign_gpo_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "FOREIGN\\GPOAdmin"}], "count": 1}
        mock_api.domains.get_foreign_gpo_controllers.return_value = fake_controllers
        
        result_json = main.get_foreign_gpo_controllers("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_foreign_gpo_controllers.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "foreign_gpo_controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_foreign_groups(self, mock_api):
        """Test get_foreign_groups MCP tool"""
        fake_groups = {"data": [{"objectid": "grp1", "name": "FOREIGN\\CrossDomainGroup"}], "count": 1}
        mock_api.domains.get_foreign_groups.return_value = fake_groups
        
        result_json = main.get_foreign_groups("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_foreign_groups.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "foreign_groups" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_foreign_users(self, mock_api):
        """Test get_foreign_users MCP tool"""
        fake_users = {"data": [{"objectid": "user1", "name": "FOREIGN\\CrossUser"}], "count": 1}
        mock_api.domains.get_foreign_users.return_value = fake_users
        
        result_json = main.get_foreign_users("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_foreign_users.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "foreign_users" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_inbound_trusts(self, mock_api):
        """Test get_inbound_trusts MCP tool"""
        fake_trusts = {"data": [{"objectid": "trust1", "name": "TRUSTED.DOMAIN"}], "count": 1}
        mock_api.domains.get_inbound_trusts.return_value = fake_trusts
        
        result_json = main.get_inbound_trusts("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_inbound_trusts.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "inbound_trusts" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_outbound_trusts(self, mock_api):
        """Test get_outbound_trusts MCP tool"""
        fake_trusts = {"data": [{"objectid": "trust1", "name": "OUTBOUND.DOMAIN"}], "count": 1}
        mock_api.domains.get_outbound_trusts.return_value = fake_trusts
        
        result_json = main.get_outbound_trusts("domain_id_123")
        result = json.loads(result_json)
        
        mock_api.domains.get_outbound_trusts.assert_called_once_with("domain_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "outbound_trusts" in result


class TestUserMCPTools:
    """Test all user-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_info(self, mock_api):
        """Test get_user_info MCP tool"""
        fake_user = {"data": {"objectid": "user1", "name": "john.doe@domain.local"}}
        mock_api.users.get_info.return_value = fake_user
        
        result_json = main.get_user_info("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_info.assert_called_once_with("user_id_123")
        assert "user_info" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_admin_rights(self, mock_api):
        """Test get_user_admin_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "SERVER01"}], "count": 1}
        mock_api.users.get_admin_rights.return_value = fake_rights
        
        result_json = main.get_user_admin_rights("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_admin_rights.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_admin_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_constrained_delegation_rights(self, mock_api):
        """Test get_user_constrained_delegation_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "svc1", "name": "SERVICE01"}], "count": 1}
        mock_api.users.get_constrained_delegation_rights.return_value = fake_rights
        
        result_json = main.get_user_constrained_delegation_rights("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_constrained_delegation_rights.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_constrained_delegation_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_controllables(self, mock_api):
        """Test get_user_controllables MCP tool"""
        fake_controllables = {"data": [{"objectid": "obj1", "name": "CONTROLLED_OBJECT"}], "count": 1}
        mock_api.users.get_controllables.return_value = fake_controllables
        
        result_json = main.get_user_controllables("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_controllables.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_controlables" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_controllers(self, mock_api):
        """Test get_user_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "DOMAIN_ADMIN"}], "count": 1}
        mock_api.users.get_controllers.return_value = fake_controllers
        
        result_json = main.get_user_controllers("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_controllers.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_dcom_rights(self, mock_api):
        """Test get_user_dcom_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "TARGET_COMP"}], "count": 1}
        mock_api.users.get_dcom_rights.return_value = fake_rights
        
        result_json = main.get_user_dcom_rights("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_dcom_rights.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_dcom_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_memberships(self, mock_api):
        """Test get_user_memberships MCP tool"""
        fake_memberships = {"data": [{"objectid": "grp1", "name": "IT_ADMINS"}], "count": 1}
        mock_api.users.get_memberships.return_value = fake_memberships
        
        result_json = main.get_user_memberships("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_memberships.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_memberships" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_ps_remote_rights(self, mock_api):
        """Test get_user_ps_remote_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "PS_TARGET"}], "count": 1}
        mock_api.users.get_ps_remote_rights.return_value = fake_rights
        
        result_json = main.get_user_ps_remote_rights("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_ps_remote_rights.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_ps_remote_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_rdp_rights(self, mock_api):
        """Test get_user_rdp_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "RDP_TARGET"}], "count": 1}
        mock_api.users.get_rdp_rights.return_value = fake_rights
        
        result_json = main.get_user_rdp_rights("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_rdp_rights.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_rdp_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_sessions(self, mock_api):
        """Test get_user_sessions MCP tool"""
        fake_sessions = {"data": [{"objectid": "comp1", "name": "SESSION_HOST"}], "count": 1}
        mock_api.users.get_sessions.return_value = fake_sessions
        
        result_json = main.get_user_sessions("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_sessions.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_sessions" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_user_sql_admin_rights(self, mock_api):
        """Test get_user_sql_admin_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "sql1", "name": "SQL_SERVER"}], "count": 1}
        mock_api.users.get_sql_admin_rights.return_value = fake_rights
        
        result_json = main.get_user_sql_admin_rights("user_id_123")
        result = json.loads(result_json)
        
        mock_api.users.get_sql_admin_rights.assert_called_once_with("user_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "user_sql_admin_rights" in result


class TestGroupMCPTools:
    """Test all group-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_info(self, mock_api):
        """Test get_group_info MCP tool"""
        fake_group = {"data": {"objectid": "grp1", "name": "Domain Admins@domain.local"}}
        mock_api.groups.get_info.return_value = fake_group
        
        result_json = main.get_group_info("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_info.assert_called_once_with("group_id_123")
        assert "group_info" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_admin_rights(self, mock_api):
        """Test get_group_admin_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "SERVER01"}], "count": 1}
        mock_api.groups.get_admin_rights.return_value = fake_rights
        
        result_json = main.get_group_admin_rights("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_admin_rights.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_admin_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_controllables(self, mock_api):
        """Test get_group_controllables MCP tool"""
        fake_controllables = {"data": [{"objectid": "obj1", "name": "CONTROLLED_OBJECT"}], "count": 1}
        mock_api.groups.get_controllables.return_value = fake_controllables
        
        result_json = main.get_group_controllables("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_controllables.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_controlables" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_controllers(self, mock_api):
        """Test get_group_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "CONTROLLER"}], "count": 1}
        mock_api.groups.get_controllers.return_value = fake_controllers
        
        result_json = main.get_group_controllers("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_controllers.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_dcom_rights(self, mock_api):
        """Test get_group_dcom_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "DCOM_TARGET"}], "count": 1}
        mock_api.groups.get_dcom_rights.return_value = fake_rights
        
        result_json = main.get_group_dcom_rights("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_dcom_rights.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_dcom_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_members(self, mock_api):
        """Test get_group_members MCP tool"""
        fake_members = {"data": [{"objectid": "user1", "name": "member1@domain.local"}], "count": 1}
        mock_api.groups.get_members.return_value = fake_members
        
        result_json = main.get_group_members("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_members.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_members" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_memberships(self, mock_api):
        """Test get_group_memberships MCP tool"""
        fake_memberships = {"data": [{"objectid": "grp1", "name": "PARENT_GROUP"}], "count": 1}
        mock_api.groups.get_memberships.return_value = fake_memberships
        
        result_json = main.get_group_memberships("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_memberships.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_memberships" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_ps_remote_rights(self, mock_api):
        """Test get_group_ps_remote_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "PS_TARGET"}], "count": 1}
        mock_api.groups.get_ps_remote_rights.return_value = fake_rights
        
        result_json = main.get_group_ps_remote_rights("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_ps_remote_rights.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_ps_remote_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_rdp_rights(self, mock_api):
        """Test get_group_rdp_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "RDP_TARGET"}], "count": 1}
        mock_api.groups.get_rdp_rights.return_value = fake_rights
        
        result_json = main.get_group_rdp_rights("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_rdp_rights.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_rdp_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_group_sessions(self, mock_api):
        """Test get_group_sessions MCP tool"""
        fake_sessions = {"data": [{"objectid": "comp1", "name": "SESSION_HOST"}], "count": 1}
        mock_api.groups.get_sessions.return_value = fake_sessions
        
        result_json = main.get_group_sessions("group_id_123")
        result = json.loads(result_json)
        
        mock_api.groups.get_sessions.assert_called_once_with("group_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "group_sessions" in result


class TestComputerMCPTools:
    """Test all computer-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_info(self, mock_api):
        """Test get_computer_info MCP tool"""
        fake_computer = {"data": {"objectid": "comp1", "name": "SERVER01.domain.local"}}
        mock_api.computers.get_info.return_value = fake_computer
        
        result_json = main.get_computer_info("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_info.assert_called_once_with("computer_id_123")
        assert "computer_info" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_admin_rights(self, mock_api):
        """Test get_computer_admin_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "TARGET_COMP"}], "count": 1}
        mock_api.computers.get_admin_rights.return_value = fake_rights
        
        result_json = main.get_computer_admin_rights("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_admin_rights.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_admin_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_admin_users(self, mock_api):
        """Test get_computer_admin_users MCP tool"""
        fake_users = {"data": [{"objectid": "user1", "name": "admin@domain.local"}], "count": 1}
        mock_api.computers.get_admin_users.return_value = fake_users
        
        result_json = main.get_computer_admin_users("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_admin_users.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_admin_users" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_constrained_delegation_rights(self, mock_api):
        """Test get_computer_constrained_delegation_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "svc1", "name": "SERVICE01"}], "count": 1}
        mock_api.computers.get_constrained_delegation_rights.return_value = fake_rights
        
        result_json = main.get_computer_constrained_delegation_rights("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_constrained_delegation_rights.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_constrained_delegation_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_constrained_users(self, mock_api):
        """Test get_computer_constrained_users MCP tool"""
        fake_users = {"data": [{"objectid": "user1", "name": "delegated@domain.local"}], "count": 1}
        mock_api.computers.get_constrained_users.return_value = fake_users
        
        result_json = main.get_computer_constrained_users("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_constrained_users.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_constrained_users" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_controllables(self, mock_api):
        """Test get_computer_controllables MCP tool"""
        fake_controllables = {"data": [{"objectid": "obj1", "name": "CONTROLLED"}], "count": 1}
        mock_api.computers.get_controllables.return_value = fake_controllables
        
        result_json = main.get_computer_controllables("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_controllables.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_controlables" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_controllers(self, mock_api):
        """Test get_computer_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "CONTROLLER"}], "count": 1}
        mock_api.computers.get_controllers.return_value = fake_controllers
        
        result_json = main.get_computer_controllers("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_controllers.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_dcom_rights(self, mock_api):
        """Test get_computer_dcom_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "DCOM_TARGET"}], "count": 1}
        mock_api.computers.get_dcom_rights.return_value = fake_rights
        
        result_json = main.get_computer_dcom_rights("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_dcom_rights.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_dcom_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_dcom_users(self, mock_api):
        """Test get_computer_dcom_users MCP tool"""
        fake_users = {"data": [{"objectid": "user1", "name": "dcom_user@domain.local"}], "count": 1}
        mock_api.computers.get_dcom_users.return_value = fake_users
        
        result_json = main.get_computer_dcom_users("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_dcom_users.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_dcom_users" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_memberships(self, mock_api):
        """Test get_computer_memberships MCP tool"""
        fake_memberships = {"data": [{"objectid": "grp1", "name": "COMPUTER_GROUP"}], "count": 1}
        mock_api.computers.get_memberships.return_value = fake_memberships
        
        result_json = main.get_computer_memberships("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_memberships.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_memberships" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_ps_remote_rights(self, mock_api):
        """Test get_computer_ps_remote_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "PS_TARGET"}], "count": 1}
        mock_api.computers.get_ps_remote_rights.return_value = fake_rights
        
        result_json = main.get_computer_ps_remote_rights("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_ps_remote_rights.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_ps_remote_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_ps_remote_users(self, mock_api):
        """Test get_computer_ps_remote_users MCP tool"""
        fake_users = {"data": [{"objectid": "user1", "name": "ps_user@domain.local"}], "count": 1}
        mock_api.computers.get_ps_remote_users.return_value = fake_users
        
        result_json = main.get_computer_ps_remote_users("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_ps_remote_users.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_ps_remote_users" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_rdp_rights(self, mock_api):
        """Test get_computer_rdp_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "comp1", "name": "RDP_TARGET"}], "count": 1}
        mock_api.computers.get_rdp_rights.return_value = fake_rights
        
        result_json = main.get_computer_rdp_rights("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_rdp_rights.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_rdp_rights" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_rdp_users(self, mock_api):
        """Test get_computer_rdp_users MCP tool"""
        fake_users = {"data": [{"objectid": "user1", "name": "rdp_user@domain.local"}], "count": 1}
        mock_api.computers.get_rdp_users.return_value = fake_users
        
        result_json = main.get_computer_rdp_users("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_rdp_users.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_rdp_users" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_sessions(self, mock_api):
        """Test get_computer_sessions MCP tool"""
        fake_sessions = {"data": [{"objectid": "user1", "name": "session_user@domain.local"}], "count": 1}
        mock_api.computers.get_sessions.return_value = fake_sessions
        
        result_json = main.get_computer_sessions("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_sessions.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_sessions" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_computer_sql_admin_rights(self, mock_api):
        """Test get_computer_sql_admin_rights MCP tool"""
        fake_rights = {"data": [{"objectid": "sql1", "name": "SQL_SERVER"}], "count": 1}
        mock_api.computers.get_sql_admin_rights.return_value = fake_rights
        
        result_json = main.get_computer_sql_admin_rights("computer_id_123")
        result = json.loads(result_json)
        
        mock_api.computers.get_sql_admin_rights.assert_called_once_with("computer_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "computer_sql_admin_rights" in result


class TestOUMCPTools:
    """Test all OU-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_ou_info(self, mock_api):
        """Test get_ou_info MCP tool"""
        fake_ou = {"data": {"objectid": "ou1", "name": "Domain Controllers"}}
        mock_api.ous.get_info.return_value = fake_ou
        
        result_json = main.get_ou_info("ou_id_123")
        result = json.loads(result_json)
        
        mock_api.ous.get_info.assert_called_once_with("ou_id_123")
        assert "ou_info" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_ou_computers(self, mock_api):
        """Test get_ou_computers MCP tool"""
        fake_computers = {"data": [{"objectid": "comp1", "name": "DC01"}], "count": 1}
        mock_api.ous.get_computers.return_value = fake_computers
        
        result_json = main.get_ou_computers("ou_id_123")
        result = json.loads(result_json)
        
        mock_api.ous.get_computers.assert_called_once_with("ou_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "ou_computers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_ou_groups(self, mock_api):
        """Test get_ou_groups MCP tool"""
        fake_groups = {"data": [{"objectid": "grp1", "name": "OU_GROUP"}], "count": 1}
        mock_api.ous.get_groups.return_value = fake_groups
        
        result_json = main.get_ou_groups("ou_id_123")
        result = json.loads(result_json)
        
        mock_api.ous.get_groups.assert_called_once_with("ou_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "ou_groups" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_ou_gpos(self, mock_api):
        """Test get_ou_gpos MCP tool"""
        fake_gpos = {"data": [{"objectid": "gpo1", "name": "OU_POLICY"}], "count": 1}
        mock_api.ous.get_gpos.return_value = fake_gpos
        
        result_json = main.get_ou_gpos("ou_id_123")
        result = json.loads(result_json)
        
        mock_api.ous.get_gpos.assert_called_once_with("ou_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "ou_gpos" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_ou_users(self, mock_api):
        """Test get_ou_users MCP tool"""
        fake_users = {"data": [{"objectid": "user1", "name": "ou_user@domain.local"}], "count": 1}
        mock_api.ous.get_users.return_value = fake_users
        
        result_json = main.get_ou_users("ou_id_123")
        result = json.loads(result_json)
        
        mock_api.ous.get_users.assert_called_once_with("ou_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "ou_users" in result


class TestGPOMCPTools:
    """Test all GPO-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_gpo_info(self, mock_api):
        """Test get_gpo_info MCP tool"""
        fake_gpo = {"data": {"objectid": "gpo1", "name": "Default Domain Policy"}}
        mock_api.gpos.get_info.return_value = fake_gpo
        
        result_json = main.get_gpo_info("gpo_id_123")
        result = json.loads(result_json)
        
        mock_api.gpos.get_info.assert_called_once_with("gpo_id_123")
        assert "gpo_info" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_gpo_computers(self, mock_api):
        """Test get_gpo_computers MCP tool"""
        fake_computers = {"data": [{"objectid": "comp1", "name": "TARGET_COMP"}], "count": 1}
        mock_api.gpos.get_computers.return_value = fake_computers
        
        result_json = main.get_gpo_computers("gpo_id_123")
        result = json.loads(result_json)
        
        mock_api.gpos.get_computers.assert_called_once_with("gpo_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "gpo_computers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_gpo_controllers(self, mock_api):
        """Test get_gpo_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "GPO_CONTROLLER"}], "count": 1}
        mock_api.gpos.get_controllers.return_value = fake_controllers
        
        result_json = main.get_gpo_controllers("gpo_id_123")
        result = json.loads(result_json)
        
        mock_api.gpos.get_controllers.assert_called_once_with("gpo_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "gpo_controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_gpo_ous(self, mock_api):
        """Test get_gpo_ous MCP tool"""
        fake_ous = {"data": [{"objectid": "ou1", "name": "TARGET_OU"}], "count": 1}
        mock_api.gpos.get_ous.return_value = fake_ous
        
        result_json = main.get_gpo_ous("gpo_id_123")
        result = json.loads(result_json)
        
        mock_api.gpos.get_ous.assert_called_once_with("gpo_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "gpo_ous" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_gpo_tier_zeros(self, mock_api):
        """Test get_gpo_tier_zeros MCP tool"""
        fake_tier_zeros = {"data": [{"objectid": "tz1", "name": "TIER_ZERO"}], "count": 1}
        mock_api.gpos.get_tier_zeros.return_value = fake_tier_zeros
        
        result_json = main.get_gpo_tier_zeros("gpo_id_123", 0, 100)
        result = json.loads(result_json)
        
        mock_api.gpos.get_tier_zeros.assert_called_once_with("gpo_id_123", limit=0, skip=100)
        assert result["count"] == 1
        assert "gpo_tier_zeros" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_gpo_users(self, mock_api):
        """Test get_gpo_users MCP tool"""
        fake_users = {"data": [{"objectid": "user1", "name": "gpo_user@domain.local"}], "count": 1}
        mock_api.gpos.get_users.return_value = fake_users
        
        result_json = main.get_gpo_users("gpo_id_123")
        result = json.loads(result_json)
        
        mock_api.gpos.get_users.assert_called_once_with("gpo_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "gpo_users" in result


class TestGraphMCPTools:
    """Test all graph-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_search_graph(self, mock_api):
        """Test search_graph MCP tool"""
        fake_results = {"data": [{"objectid": "node1", "name": "TARGET_NODE"}]}
        mock_api.graph.search.return_value = fake_results
        
        result_json = main.search_graph("Domain Admins", "fuzzy")
        result = json.loads(result_json)
        
        mock_api.graph.search.assert_called_once_with("Domain Admins", "fuzzy")
        assert "results" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_shortest_path(self, mock_api):
        """Test get_shortest_path MCP tool"""
        fake_path = {"data": {"nodes": [], "edges": []}}
        mock_api.graph.get_shortest_path.return_value = fake_path
        
        result_json = main.get_shortest_path("start_node", "end_node")
        result = json.loads(result_json)
        
        mock_api.graph.get_shortest_path.assert_called_once_with("start_node", "end_node", None)
        assert "path" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_edge_composition(self, mock_api):
        """Test get_edge_composition MCP tool"""
        fake_composition = {"data": {"components": []}}
        mock_api.graph.get_edge_composition.return_value = fake_composition
        
        result_json = main.get_edge_composition(123, 456, "AdminTo")
        result = json.loads(result_json)
        
        mock_api.graph.get_edge_composition.assert_called_once_with(123, 456, "AdminTo")
        assert "composition" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_relay_targets(self, mock_api):
        """Test get_relay_targets MCP tool"""
        fake_targets = {"data": {"targets": []}}
        mock_api.graph.get_relay_targets.return_value = fake_targets
        
        result_json = main.get_relay_targets(123, 456, "CanRDP")
        result = json.loads(result_json)
        
        mock_api.graph.get_relay_targets.assert_called_once_with(123, 456, "CanRDP")
        assert "targets" in result


class TestADCSMCPTools:
    """Test all ADCS-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_cert_template_info(self, mock_api):
        """Test get_cert_template_info MCP tool"""
        fake_template = {"data": {"objectid": "tmpl1", "name": "User Certificate"}}
        mock_api.adcs.get_cert_template_info.return_value = fake_template
        
        result_json = main.get_cert_template_info("template_id_123")
        result = json.loads(result_json)
        
        mock_api.adcs.get_cert_template_info.assert_called_once_with("template_id_123")
        assert "cert_template_info" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_cert_template_controllers(self, mock_api):
        """Test get_cert_template_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "PKI_ADMIN"}], "count": 1}
        mock_api.adcs.get_cert_template_controllers.return_value = fake_controllers
        
        result_json = main.get_cert_template_controllers("template_id_123")
        result = json.loads(result_json)
        
        mock_api.adcs.get_cert_template_controllers.assert_called_once_with("template_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "cert_template_controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_root_ca_info(self, mock_api):
        """Test get_root_ca_info MCP tool"""
        fake_ca = {"data": {"objectid": "ca1", "name": "Root CA"}}
        mock_api.adcs.get_root_ca_info.return_value = fake_ca
        
        result_json = main.get_root_ca_info("ca_id_123")
        result = json.loads(result_json)
        
        mock_api.adcs.get_root_ca_info.assert_called_once_with("ca_id_123")
        assert "root_ca_info" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_root_ca_controllers(self, mock_api):
        """Test get_root_ca_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "CA_ADMIN"}], "count": 1}
        mock_api.adcs.get_root_ca_controllers.return_value = fake_controllers
        
        result_json = main.get_root_ca_controllers("ca_id_123")
        result = json.loads(result_json)
        
        mock_api.adcs.get_root_ca_controllers.assert_called_once_with("ca_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "root_ca_controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_enterprise_ca_info(self, mock_api):
        """Test get_enterprise_ca_info MCP tool"""
        fake_ca = {"data": {"objectid": "eca1", "name": "Enterprise CA"}}
        mock_api.adcs.get_enterprise_ca_info.return_value = fake_ca
        
        result_json = main.get_enterprise_ca_info("ca_id_123")
        result = json.loads(result_json)
        
        mock_api.adcs.get_enterprise_ca_info.assert_called_once_with("ca_id_123")
        assert "enterprise_ca_info" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_enterprise_ca_controllers(self, mock_api):
        """Test get_enterprise_ca_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "ENT_CA_ADMIN"}], "count": 1}
        mock_api.adcs.get_enterprise_ca_controllers.return_value = fake_controllers
        
        result_json = main.get_enterprise_ca_controllers("ca_id_123")
        result = json.loads(result_json)
        
        mock_api.adcs.get_enterprise_ca_controllers.assert_called_once_with("ca_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "enterprise_ca_controllers" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_aia_ca_controllers(self, mock_api):
        """Test get_aia_ca_controllers MCP tool"""
        fake_controllers = {"data": [{"objectid": "ctrl1", "name": "AIA_CA_ADMIN"}], "count": 1}
        mock_api.adcs.get_aia_ca_controllers.return_value = fake_controllers
        
        result_json = main.get_aia_ca_controllers("ca_id_123")
        result = json.loads(result_json)
        
        mock_api.adcs.get_aia_ca_controllers.assert_called_once_with("ca_id_123", limit=100, skip=0)
        assert result["count"] == 1
        assert "aia_ca_controllers" in result


class TestCypherMCPTools:
    """Test Cypher-related MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_run_cypher_query(self, mock_api):
        """Test run_cypher_query MCP tool"""
        fake_results = {"data": {"nodes": [], "edges": []}}
        mock_api.cypher.run_query.return_value = fake_results
        
        result_json = main.run_cypher_query("MATCH (n) RETURN n LIMIT 10")
        result = json.loads(result_json)
        
        mock_api.cypher.run_query.assert_called_once_with("MATCH (n) RETURN n LIMIT 10", True)
        assert "result" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_create_saved_query(self, mock_api):
        """Test create_saved_query MCP tool"""
        fake_query = {"data": {"id": 123, "name": "My Query"}}
        mock_api.cypher.create_saved_query.return_value = fake_query
        
        result_json = main.create_saved_query("Test Query", "MATCH (n) RETURN n")
        result = json.loads(result_json)
        
        mock_api.cypher.create_saved_query.assert_called_once_with("Test Query", "MATCH (n) RETURN n")
        assert "query" in result

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_list_saved_queries(self, mock_api):
        """Test list_saved_queries MCP tool"""
        fake_queries = {"data": [{"id": 123, "name": "Query 1"}]}
        mock_api.cypher.list_saved_queries.return_value = fake_queries
        
        result_json = main.list_saved_queries()
        result = json.loads(result_json)
        
        mock_api.cypher.list_saved_queries.assert_called_once_with(0, 100, None)
        assert "queries" in result


class TestErrorHandling:
    """Test error handling across all MCP tools"""

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_domain_tool_error_handling(self, mock_api):
        """Test error handling in domain tools"""
        mock_api.domains.get_all.side_effect = Exception("API Error")
        
        result_json = main.get_domains()
        result = json.loads(result_json)
        
        assert "error" in result
        assert "Failed to retrieve domains" in result["error"]

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_user_tool_error_handling(self, mock_api):
        """Test error handling in user tools"""
        mock_api.users.get_info.side_effect = Exception("User not found")
        
        result_json = main.get_user_info("nonexistent_user")
        result = json.loads(result_json)
        
        assert "error" in result
        assert "Failed to retrieve user info" in result["error"]

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_cypher_tool_error_handling(self, mock_api):
        """Test error handling in Cypher tools"""
        mock_api.cypher.run_query.side_effect = Exception("Invalid query")
        
        result_json = main.run_cypher_query("INVALID QUERY")
        result = json.loads(result_json)
        
        assert "error" in result
        assert "Failed to execute Cypher query" in result["error"]