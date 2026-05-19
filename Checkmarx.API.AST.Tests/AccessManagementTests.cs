using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AccessManagementTests
    {
        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<AccessManagementTests>();

            Configuration = builder.Build();

            string astServer = Configuration["ASTServer"];
            string accessControl = Configuration["AccessControlServer"];

            astclient = new ASTClient(
                new System.Uri(astServer),
                new System.Uri(accessControl),
                Configuration["Tenant"],
                Configuration["API_KEY"]);
        }

        [TestInitialize]
        public void EnsureConnected()
        {
            Assert.IsTrue(astclient.Connected);
        }

        #region Roles

        [TestMethod]
        public void GetRolesTest()
        {
            var roles = astclient.AccessManagement.GetRolesAsync().Result;

            Assert.IsNotNull(roles);
            Assert.IsTrue(roles.Any());

            foreach (var role in roles)
            {
                Trace.WriteLine($"Role: {role.Id} | {role.Name} | SystemRole={role.SystemRole} | Permissions={role.Permissions?.Count ?? 0}");
            }
        }

        [TestMethod]
        public void GetPermissionsTest()
        {
            var permissions = astclient.AccessManagement.GetPermissionsAsync().Result;

            Assert.IsNotNull(permissions);
            Assert.IsTrue(permissions.Any());

            foreach (var permission in permissions)
            {
                Trace.WriteLine($"Permission: {permission.Id} | {permission.Name} | {permission.Description}");
            }
        }

        [TestMethod]
        public void GetRoleByIdTest()
        {
            var roles = astclient.AccessManagement.GetRolesAsync().Result;
            Assert.IsNotNull(roles);
            Assert.IsTrue(roles.Any());

            var firstRole = roles.First();
            var role = astclient.AccessManagement.GetRoleAsync(System.Guid.Parse(firstRole.Id)).Result;

            Assert.IsNotNull(role);
            Assert.AreEqual(firstRole.Id, role.Id);
            Trace.WriteLine($"Role: {role.Id} | {role.Name} | Permissions: {string.Join(", ", role.Permissions ?? new List<string>())}");
        }

        [TestMethod]
        public void CreateUpdateDeleteCustomRoleTest()
        {
            string roleName = $"TestRole_{Guid.NewGuid():N}";

            var permissions = astclient.AccessManagement.GetPermissionsAsync().Result;
            Assert.IsNotNull(permissions);

            var firstPermission = permissions.FirstOrDefault();

            var createRequest = new CreateRoleRequest
            {
                Name = roleName,
                Description = "Automated test role",
                Permissions = firstPermission != null
                    ? new List<string> { firstPermission.Id }
                    : new List<string>()
            };

            astclient.AccessManagement.CreateRoleAsync(createRequest).Wait();
            Trace.WriteLine($"Created role: {roleName}");

            var roles = astclient.AccessManagement.GetRolesAsync().Result;
            var createdRole = roles.FirstOrDefault(r => r.Name == roleName);
            Assert.IsNotNull(createdRole, $"Role '{roleName}' was not found after creation.");

            var updateRequest = new CreateRoleRequest
            {
                Name = roleName,
                Description = "Updated description",
                Permissions = createdRole.Permissions ?? new List<string>()
            };

            astclient.AccessManagement.UpdateRoleAsync(System.Guid.Parse(createdRole.Id), updateRequest).Wait();
            Trace.WriteLine($"Updated role: {roleName}");

            var updatedRole = astclient.AccessManagement.GetRoleAsync(System.Guid.Parse(createdRole.Id)).Result;
            Assert.AreEqual("Updated description", updatedRole.Description);

            astclient.AccessManagement.DeleteRoleAsync(System.Guid.Parse(createdRole.Id)).Wait();
            Trace.WriteLine($"Deleted role: {roleName}");

            var rolesAfterDelete = astclient.AccessManagement.GetRolesAsync().Result;
            Assert.IsFalse(rolesAfterDelete.Any(r => r.Id == createdRole.Id), "Role should have been deleted.");
        }

        #endregion

        #region User Permissions and Assignments

        [TestMethod]
        public void GetUsersTest()
        {
            var users = astclient.AccessManagement.GetUsersAsync().Result;

            Assert.IsNotNull(users);
            Assert.IsTrue(users.Any());

            foreach (var user in users)
            {
                Trace.WriteLine($"User: {user.Id} | {user.Username} | {user.Email}");
            }
        }

        [TestMethod]
        public void GetUserResourcesForTest()
        {
            string userId = Configuration["TestUserId"];

            if (string.IsNullOrWhiteSpace(userId))
            {
                var users = astclient.AccessManagement.GetUsersAsync(limit: 1).Result;
                Assert.IsTrue(users.Any(), "No users found in the tenant.");
                userId = users.First().Id.ToString();
            }

            var assignments = astclient.AccessManagement.GetResourcesForAsync(userId, null).Result;

            Assert.IsNotNull(assignments);

            foreach (var assignment in assignments)
            {
                Trace.WriteLine($"Assignment: EntityId={assignment.EntityID} | ResourceId={assignment.ResourceID} | ResourceType={assignment.ResourceType} | Roles={string.Join(", ", assignment.EntityRoles?.Select(r => r.Name) ?? Enumerable.Empty<string>())}");
            }
        }

        [TestMethod]
        public void GetBaseRolesForUserTest()
        {
            string userId = Configuration["TestUserId"];

            if (string.IsNullOrWhiteSpace(userId))
            {
                var users = astclient.AccessManagement.GetUsersAsync(limit: 1).Result;
                Assert.IsTrue(users.Any(), "No users found in the tenant.");
                userId = users.First().Id.ToString();
            }

            var baseRoles = astclient.AccessManagement.GetBaseRolesForEntityAsync(System.Guid.Parse(userId)).Result;

            Assert.IsNotNull(baseRoles);
            Trace.WriteLine($"EntityID={baseRoles.EntityID} | BaseRoles={string.Join(", ", baseRoles.BaseRoles ?? new List<string>())}");
        }

        [TestMethod]
        public void UpdateBaseRolesForUserTest()
        {
            string userId = Configuration["TestUserId"];
            Assert.IsFalse(string.IsNullOrWhiteSpace(userId), "TestUserId must be set in user secrets to run this test.");

            var currentBaseRoles = astclient.AccessManagement.GetBaseRolesForEntityAsync(System.Guid.Parse(userId)).Result;
            var originalRoles = currentBaseRoles.BaseRoles?.ToList() ?? new List<string>();

            Trace.WriteLine($"Original base roles: {string.Join(", ", originalRoles)}");

            var roles = astclient.AccessManagement.GetRolesAsync().Result;
            var nonSystemRole = roles.FirstOrDefault(r => r.SystemRole == false);

            if (nonSystemRole == null)
            {
                Assert.Inconclusive("No custom roles found; cannot update base roles without a non-system role.");
                return;
            }

            var newRoles = new List<string>(originalRoles);
            if (!newRoles.Contains(nonSystemRole.Name))
                newRoles.Add(nonSystemRole.Name);

            var updateRequest = new BaseRolesRequest { BaseRoles = newRoles };
            astclient.AccessManagement.UpdateBaseRolesAsync(System.Guid.Parse(userId), updateRequest).Wait();
            Trace.WriteLine($"Updated base roles to: {string.Join(", ", newRoles)}");

            var updatedBaseRoles = astclient.AccessManagement.GetBaseRolesForEntityAsync(System.Guid.Parse(userId)).Result;
            Assert.IsTrue(updatedBaseRoles.BaseRoles?.Contains(nonSystemRole.Name) == true);

            var restoreRequest = new BaseRolesRequest { BaseRoles = originalRoles };
            astclient.AccessManagement.UpdateBaseRolesAsync(System.Guid.Parse(userId), restoreRequest).Wait();
            Trace.WriteLine("Restored original base roles.");
        }

        [TestMethod]
        public void UpdateEntityRolesForAssignmentTest()
        {
            string userId = Configuration["TestUserId"];
            string resourceId = Configuration["TestResourceId"];

            Assert.IsFalse(string.IsNullOrWhiteSpace(userId), "TestUserId must be set in user secrets.");
            Assert.IsFalse(string.IsNullOrWhiteSpace(resourceId), "TestResourceId must be set in user secrets.");

            var assignment = astclient.AccessManagement.GetAssignmentAsync(userId, resourceId).Result;
            Assert.IsNotNull(assignment);

            var originalRoleNames = assignment.EntityRoles?.Select(r => r.Name).ToList() ?? new List<string>();
            Trace.WriteLine($"Original entity roles: {string.Join(", ", originalRoleNames)}");

            var roles = astclient.AccessManagement.GetRolesAsync().Result;
            var availableRole = roles.FirstOrDefault(r => !originalRoleNames.Contains(r.Name));

            if (availableRole == null)
            {
                Assert.Inconclusive("No additional roles available to add to the assignment.");
                return;
            }

            var newRoles = new List<string>(originalRoleNames) { availableRole.Name };
            var updateRequest = new EntityRolesRequest { NewEntityRoles = newRoles };
            astclient.AccessManagement.UpdateEntityRolesAsync(userId, resourceId, updateRequest).Wait();
            Trace.WriteLine($"Updated entity roles to: {string.Join(", ", newRoles)}");

            var updatedAssignment = astclient.AccessManagement.GetAssignmentAsync(userId, resourceId).Result;
            Assert.IsTrue(updatedAssignment.EntityRoles?.Any(r => r.Name == availableRole.Name) == true);

            var restoreRequest = new EntityRolesRequest { NewEntityRoles = originalRoleNames };
            astclient.AccessManagement.UpdateEntityRolesAsync(userId, resourceId, restoreRequest).Wait();
            Trace.WriteLine("Restored original entity roles.");
        }

        [TestMethod]
        public void GetEffectivePermissionsForUserTest()
        {
            string userId = Configuration["TestUserId"];

            if (string.IsNullOrWhiteSpace(userId))
            {
                var users = astclient.AccessManagement.GetUsersAsync(limit: 1).Result;
                Assert.IsTrue(users.Any(), "No users found in the tenant.");
                userId = users.First().Id.ToString();
            }

            var effectivePermissions = astclient.AccessManagement
                .GetEffectivePermissionsToResourceAsync(System.Guid.Parse(userId), "user", "tenant").Result;

            Assert.IsNotNull(effectivePermissions);
            Trace.WriteLine($"EntityId={effectivePermissions.EntityId} | ResourceType={effectivePermissions.ResourceType}");
            Trace.WriteLine($"Permissions: {string.Join(", ", effectivePermissions.Permissions ?? new List<string>())}");
        }

        #endregion

        #region Groups

        [TestMethod]
        public void GetGroupsTest()
        {
            var groups = astclient.AccessManagement.GetGroupsAsync().Result;

            Assert.IsNotNull(groups);

            foreach (var group in groups.Take(10))
            {
                Trace.WriteLine($"Group: {group.Id} | {group.Name}");
            }
        }

        [TestMethod]
        public void GetAvailableGroupsTest()
        {
            var result = astclient.AccessManagement.GetEntityAvailableGroupsAsync().Result;

            Assert.IsNotNull(result);
            Trace.WriteLine($"Total available groups: {result.Total}");

            foreach (var group in result.Groups?.Take(10) ?? Enumerable.Empty<GroupRepresentation>())
            {
                Trace.WriteLine($"Group: {group.Id} | {group.Name} | Path={group.Path}");
            }
        }

        #endregion

        #region Users With Resources

        [TestMethod]
        public void GetUsersWithResourcesTest()
        {
            var result = astclient.AccessManagement.GetUsersWithResourcesAsync(
                search: null,
                base_roles: null,
                username: null,
                order: null,
                limit: 20,
                offset: 0).Result;

            Assert.IsNotNull(result);
            Trace.WriteLine($"Total users: {result.TotalCount} | Filtered: {result.FilteredCount}");

            foreach (var user in result.Users?.Take(5) ?? Enumerable.Empty<Users>())
            {
                Trace.WriteLine($"User: {user.Id} | {user.Username} | BaseRoles={string.Join(", ", user.BaseRoles ?? Enumerable.Empty<string>())}");
            }
        }

        #endregion
    }
}
