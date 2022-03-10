import entity.Authentication;
import entity.Role;
import entity.User;
import exception.AuthException;
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import service.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class AuthServiceImplTest {

    AuthServiceImpl authService;
    private String authToken;

    @BeforeEach
    void setup() {
        authService = new AuthServiceImpl(2, TimeUnit.SECONDS);
    }

    @Test
    void testCreateUser() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        assertTrue(authService.isUserExist(user));
    }

    @Test
    void testCreateAlreadyExistUser() throws Exception {
        authService.createUser("user", "encryptPassword");
        Exception e = assertThrows(AuthException.class, () -> {
            authService.createUser("user", "encryptPassword");
            ;
        });
        assertTrue(e.getMessage().contains("User: user already exists."));
    }

    @Test
    void testDeleteUser() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        assertTrue(authService.isUserExist(user));
        authService.deleteUser(user);
        assertFalse(authService.isUserExist(user));
    }

    @Test
    void testDeleteNonExistUser() {
        User user = new User("user", "encryptPassword");
        Exception e = assertThrows(AuthException.class, () -> {
            authService.deleteUser(user);
        });
        assertTrue(e.getMessage().contains("User: user does not exist."));
    }

    @Test
    void testCreateRole() throws Exception {
        Role role = Role.RoleA;
        authService.createRole(role);
        assertTrue(authService.isRoleExist(role));
    }

    @Test
    void testCreateAlreadyExistRole() throws Exception {
        Role role = Role.RoleA;
        authService.createRole(role);
        assertTrue(authService.isRoleExist(role));

        Exception e = assertThrows(AuthException.class, () -> {
            authService.createRole(role);
        });
        assertTrue(e.getMessage().contains("already exists."));
    }

    @Test
    void testDeleteRole() throws Exception {
        Role role = Role.RoleA;
        authService.createRole(role);
        assertTrue(authService.isRoleExist(role));
        authService.deleteRole(role);
        assertFalse(authService.isRoleExist(role));
    }

    @Test
    void testDeleteNonExistRole() {
        Role role = Role.RoleA;
        Exception e = assertThrows(AuthException.class, () -> {
            authService.deleteRole(role);
        });
        assertTrue(e.getMessage().contains("does not exist"));
    }

    @Test
    void testAddRoleToUser() throws Exception {
        Role role = Role.RoleA;
        User user = authService.createUser("user", "encryptPassword");
        authService.createRole(role);

        authService.addRoleToUser(user,  role);
        assertTrue(authService.getUserRole(user).contains(role));
        assertTrue(authService.getUserRole(user).size() == 1);
    }


    @Test
    void testAuthenticate() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        authService.authenticate("user", "encryptPassword");
        assertNotNull(authService.authenticate("user", "encryptPassword"));
    }

    @Test
    void testAuthenticateFail() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        Exception e = assertThrows(AuthException.class, () -> {
            authService.authenticate("user", "wrongEncryptPassword");
        });
        assertTrue(e.getMessage().contains("password incorrect."));
    }

    @Test
    void testAuthenticateNonExistUser() {
        Exception e = assertThrows(AuthException.class, () -> {
            authService.authenticate("user", "encryptPassword");
        });
        assertTrue(e.getMessage().contains("does not exist."));
    }

    @Test
    void testInvalidate() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        Authentication authentication =  authService.authenticate("user", "encryptPassword");
        assertTrue(authService.isAuthenticationExist(authentication));
        authService.invalidate(authentication);
        assertFalse(authService.isAuthenticationExist(authentication));

        Exception e = assertThrows(AuthException.class, () -> {
            authService.invalidate(authentication);
        });
        assertTrue(e.getMessage().contains("Authentication is invalid."));
    }

    @Test
    void testExpiredAuthentication() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        Authentication authentication = authService.authenticate("user", "encryptPassword");
        assertTrue(authService.isAuthenticationExist(authentication));

        Thread.sleep(1000*2);   // 休眠2秒

        Exception e = assertThrows(AuthException.class, () -> {
            authService.invalidate(authentication);
        });
        assertTrue(e.getMessage().contains("Authentication is invalid."));
    }


    @Test
    void testCheckRole() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        Authentication authentication = authService.authenticate("user", "encryptPassword");
        Role role = Role.RoleA;
        Role roleB = Role.RoleB;
        authService.createRole(role);
        authService.addRoleToUser(user,  role);

        assertTrue(authService.checkRole(authentication, role));
        assertFalse(authService.checkRole(authentication, roleB));
    }

    @Test
    void checkRoleWithInvalidToken() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        Authentication authentication = authService.authenticate("user", "encryptPassword");
        Role role = Role.RoleA;
        authService.createRole(role);
        authService.addRoleToUser(user,  role);
        authService.invalidate(authentication);

        Exception e = assertThrows(AuthException.class, () -> {
            authService.checkRole(authentication, role);
        });
        assertTrue(e.getMessage().contains("Authentication is invalid"));
    }

    @Test
    void testAllRoles() throws AuthException {
        User user = authService.createUser("user", "encryptPassword");
        Authentication authentication = authService.authenticate("user", "encryptPassword");
        Role role = Role.RoleA;
        authService.createRole(role);
        authService.addRoleToUser(user,  role);

        assertTrue(authService.allRoles(authentication).contains(role));
        assertTrue(authService.allRoles(authentication).size() == 1);
    }

    @Test
    void checkAllRoleWithInvalidAuthentication() throws Exception {
        User user = authService.createUser("user", "encryptPassword");
        Authentication authentication = authService.authenticate("user", "encryptPassword");
        Role role = Role.RoleA;
        authService.createRole(role);
        authService.addRoleToUser(user,  role);
        authService.invalidate(authentication);

        Exception e = assertThrows(AuthException.class, () -> {
            authService.allRoles(authentication);
        });
        assertTrue(e.getMessage().contains("Authentication is invalid"));
    }
}