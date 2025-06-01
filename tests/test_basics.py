import os
from unittest.mock import patch

import pytest

from lib.bloodhound_api import BloodhoundAuthError, BloodhoundBaseClient


class TestAbsoluteBasics:
    """
    The simplest possible tests to verify pytest is working
    """

    def test_pytest_works(self):
        """
        The most basic test - just verify pytest can run tests

        If this fails, there's something wrong with your test setup
        """
        assert True  # This should always pass
        print("🎉 Pytest is working!")

    def test_math_still_works(self):
        """
        Test basic math to verify Python is working normally
        """
        result = 2 + 2
        assert result == 4
        assert result != 5
        print(f"✅ Math works: 2 + 2 = {result}")

    def test_string_operations(self):
        """
        Test string operations like we'll use with BloodHound data
        """
        domain_name = "TESTDOMAIN.LOCAL"

        # Test string contains (like checking if something is a domain controller)
        assert "TESTDOMAIN" in domain_name
        assert "LOCAL" in domain_name

        # Test case conversion (BloodHound names are often uppercase)
        lowercase = domain_name.lower()
        assert lowercase == "testdomain.local"

        print(f"✅ String operations work: {domain_name} -> {lowercase}")


class TestBloodhoundImports:
    """
    Test that we can import your BloodHound API client
    """

    def test_can_import_bloodhound_classes(self):
        """
        Test that your BloodHound API classes can be imported

        If this fails, there's a problem with your bloodhound_api.py file
        """
        # These imports should work if your API client is properly structured
        from lib.bloodhound_api import (
            BloodhoundAPI,
            BloodhoundAuthError,
            BloodhoundBaseClient,
            BloodhoundConnectionError,
        )

        print("✅ All BloodHound API classes imported successfully")

    def test_can_create_base_client_with_params(self):
        """
        Test creating a BloodHound client with fake parameters

        This tests your client's __init__ method without making real API calls
        """
        # Create client with fake credentials (no real API calls)
        client = BloodhoundBaseClient(
            domain="test.bloodhound.local",
            token_id="fake_token_id",
            token_key="fake_token_key",
        )

        # Verify the values were stored correctly
        assert client.domain == "test.bloodhound.local"
        assert client.token_id == "fake_token_id"
        assert client.token_key == "fake_token_key"
        assert client.port == 443  # Default port
        assert client.scheme == "https"  # Default scheme

        print("✅ BloodHound client initialization works")

    @patch.dict(
        os.environ, {}, clear=True
    )  # This clears ALL environment variables for this test
    def test_client_requires_domain(self):
        """
        Test that your client properly validates required parameters

        This is important - your code should fail gracefully when misconfigured

        Note: We use @patch.dict to clear environment variables so the client
        can't fall back to them.
        """
        # This should raise a BloodhoundAuthError because domain is missing
        # and no environment variables are available
        with pytest.raises(BloodhoundAuthError) as exc_info:
            BloodhoundBaseClient(
                token_id="fake_id",
                token_key="fake_key",
                # Missing domain parameter AND no env vars!
            )

        # Check that the error message is helpful
        error_message = str(exc_info.value)
        assert "domain" in error_message.lower()

        print("✅ BloodHound client properly validates required parameters")
        print(f"   Error message: {error_message}")

    @patch.dict(os.environ, {}, clear=True)
    def test_client_requires_token_id(self):
        """
        Test that missing token_id also raises an error
        """
        with pytest.raises(BloodhoundAuthError) as exc_info:
            BloodhoundBaseClient(
                domain="test.domain.com",
                token_key="fake_key",
                # Missing token_id!
            )

        error_message = str(exc_info.value)
        assert "token id" in error_message.lower()
        print("✅ Missing token_id properly detected")

    @patch.dict(os.environ, {}, clear=True)
    def test_client_requires_token_key(self):
        """
        Test that missing token_key also raises an error
        """
        with pytest.raises(BloodhoundAuthError) as exc_info:
            BloodhoundBaseClient(
                domain="test.domain.com",
                token_id="fake_id",
                # Missing token_key!
            )

        error_message = str(exc_info.value)
        assert "token key" in error_message.lower()
        print("✅ Missing token_key properly detected")


class TestEnvironmentVariableFallbacks:
    """
    Test that your client properly uses environment variables as fallbacks

    This tests a key feature of your BloodHound client!
    """

    @patch.dict(
        os.environ,
        {
            "BLOODHOUND_DOMAIN": "env.bloodhound.local",
            "BLOODHOUND_TOKEN_ID": "env_token_id",
            "BLOODHOUND_TOKEN_KEY": "env_token_key",
        },
    )
    def test_client_uses_environment_variables(self):
        """
        Test that client falls back to environment variables

        This is actually the CORRECT behavior for your client!
        """
        # Create client without any parameters
        client = BloodhoundBaseClient()

        # Should use values from environment variables
        assert client.domain == "env.bloodhound.local"
        assert client.token_id == "env_token_id"
        assert client.token_key == "env_token_key"

        print("✅ Environment variable fallback works correctly")

    @patch.dict(
        os.environ,
        {
            "BLOODHOUND_DOMAIN": "env.bloodhound.local",
            "BLOODHOUND_TOKEN_ID": "env_token_id",
            "BLOODHOUND_TOKEN_KEY": "env_token_key",
        },
    )
    def test_parameters_override_environment(self):
        """
        Test that explicit parameters override environment variables
        """
        # Provide some parameters, leave others to come from env
        client = BloodhoundBaseClient(
            domain="override.domain.com",
            token_id="override_id",
            # token_key should come from environment
        )

        assert client.domain == "override.domain.com"  # Overridden
        assert client.token_id == "override_id"  # Overridden
        assert client.token_key == "env_token_key"  # From environment

        print("✅ Parameter override behavior works correctly")


class TestBloodhoundBasicFunctionality:
    """
    Test basic BloodHound client functionality without making real API calls
    """

    def test_url_formatting(self):
        """
        Test that your client builds URLs correctly

        This is important for making sure API calls go to the right endpoints
        """
        client = BloodhoundBaseClient(
            domain="test.bloodhound.local", token_id="fake_id", token_key="fake_key"
        )

        # Test URL formatting with leading slash
        url = client._format_url("/api/v2/domains")
        expected = "https://test.bloodhound.local:443/api/v2/domains"
        assert url == expected

        # Test URL formatting without leading slash
        url = client._format_url("api/v2/domains")
        assert url == expected  # Should be the same

        print(f"✅ URL formatting works: {url}")

    def test_parameter_validation(self):
        """
        Test different ways of creating the client
        """
        # Test with all parameters
        client = BloodhoundBaseClient(
            domain="custom.domain.com",
            token_id="custom_id",
            token_key="custom_key",
            port=8080,
            scheme="http",
        )

        assert client.domain == "custom.domain.com"
        assert client.port == 8080
        assert client.scheme == "http"

        print("✅ Custom parameters work correctly")


class TestOffensiveSecurityConcepts:
    """
    Test concepts that are important for offensive security work
    """

    def test_windows_sid_recognition(self):
        """
        Test recognizing Windows SIDs (Security Identifiers)

        In BloodHound, ObjectIDs are Windows SIDs, which are important
        for understanding AD relationships
        """
        # Example SIDs from Active Directory
        domain_sid = "S-1-5-21-123456789-1234567890-123456789"
        user_sid = "S-1-5-21-123456789-1234567890-123456789-1001"
        admin_group_sid = "S-1-5-21-123456789-1234567890-123456789-512"

        # Test SID validation
        for sid in [domain_sid, user_sid, admin_group_sid]:
            assert sid.startswith("S-1-5-21-")
            assert len(sid.split("-")) >= 6

        # Test recognizing Domain Admins group (RID 512)
        assert admin_group_sid.endswith("-512")

        print("✅ Windows SID recognition works")

    def test_bloodhound_object_types(self):
        """
        Test understanding of BloodHound object types

        These are the main types you'll see in BloodHound analysis
        """
        object_types = ["User", "Group", "Computer", "Domain", "GPO", "OU"]
        high_value_types = ["User", "Group", "Computer"]

        # All high-value types should be in the main list
        for hvt in high_value_types:
            assert hvt in object_types

        # Test filtering (like you'd do in real analysis)
        security_principals = [t for t in object_types if t in high_value_types]
        assert len(security_principals) == 3

        print(f"✅ BloodHound object types: {object_types}")
        print(f"✅ Security principals: {security_principals}")

    def test_attack_path_concepts(self):
        """
        Test basic attack path concepts

        This simulates the kind of data processing you'd do with BloodHound
        """
        # Simulate a simple attack path: User -> Group -> Admin Group
        attack_path = [
            {"type": "User", "name": "lowpriv@domain.local", "owned": True},
            {"type": "Group", "name": "IT Support@domain.local", "owned": False},
            {"type": "Group", "name": "Domain Admins@domain.local", "owned": False},
        ]

        # Find owned objects (your starting points)
        owned_objects = [obj for obj in attack_path if obj.get("owned", False)]
        assert len(owned_objects) == 1
        assert owned_objects[0]["name"] == "lowpriv@domain.local"

        # Find target (Domain Admins)
        targets = [obj for obj in attack_path if "Domain Admins" in obj["name"]]
        assert len(targets) == 1

        print("✅ Attack path analysis concepts work")
        print(f"   Start: {owned_objects[0]['name']}")
        print(f"   Target: {targets[0]['name']}")
