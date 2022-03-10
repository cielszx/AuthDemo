package service;

import entity.Authentication;
import entity.Role;
import entity.User;
import exception.AuthException;

import java.util.List;

public interface AuthService {
    User createUser(String username, String password) throws AuthException;

    void deleteUser(User user) throws AuthException;

    void createRole(Role role) throws AuthException;

    void deleteRole(Role role) throws AuthException;

    void addRoleToUser(User user, Role role);

    Authentication authenticate(String username, String password) throws AuthException;

    void invalidate(Authentication authentication) throws AuthException;

    boolean checkRole(Authentication authentication, Role role) throws AuthException;

    List<Role> allRoles(Authentication authentication) throws AuthException;
}
