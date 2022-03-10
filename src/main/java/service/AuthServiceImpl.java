package service;

import entity.Authentication;
import entity.Role;
import entity.User;
import exception.AuthException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AuthServiceImpl implements AuthService {
    private final List<User> userList = new ArrayList<>();
    private final List<Role> roleList = new ArrayList<>();
    private final Map<User, List<Role>> userRoleListMap = new HashMap<>();
    private final Map<Authentication, User> authenticationUserMap = new HashMap<>();
    private final Map<String, String> usernameEncryptPasswordMap = new HashMap<>();
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    private final int delay;
    private final TimeUnit timeUnit;

    public AuthServiceImpl(int delay, TimeUnit timeUnit){
        this.delay = delay;
        this.timeUnit = timeUnit;
    }

    @Override
    public User createUser(String username, String password) throws AuthException {
        String encryptPassword;
        if (usernameEncryptPasswordMap.containsKey(username)) {
            encryptPassword = usernameEncryptPasswordMap.get(username);
        }else {
            encryptPassword = encrypt(password);
            usernameEncryptPasswordMap.put(username, encryptPassword);
        }
        User user = new User(username, encryptPassword);
        if (userList.contains(user)) {
            throw new AuthException("User: " + user.getUsername() + " already exists.");
        }
        userList.add(user);
        return user;
    }

    @Override
    public void deleteUser(User user) throws AuthException {
        if (!userList.contains(user)) {
            throw new AuthException("User: " + user.getUsername() + " does not exist.");
        }
        userList.remove(user);
        usernameEncryptPasswordMap.remove(user.getUsername());
        userRoleListMap.remove(user);
    }

    @Override
    public void createRole(Role role) throws AuthException {
        if (roleList.contains(role)) {
            throw new AuthException("Role: " + role + " already exists.");
        }
        roleList.add(role);
    }

    @Override
    public void deleteRole(Role role) throws AuthException {
        if (!roleList.remove(role))
            throw new AuthException("Role: " + role + " does not exist.");
    }

    @Override
    public void addRoleToUser(User user, Role role) {
        if (!userRoleListMap.containsKey(user)) {
            List<Role> roleList = new ArrayList<>();
            roleList.add(role);
            userRoleListMap.put(user, roleList);
        } else {
            userRoleListMap.get(user).add(role);
        }
    }

    @Override
    public Authentication authenticate(String username, String password) throws AuthException {
        if (!usernameEncryptPasswordMap.containsKey(username)) {
            throw new AuthException("User: " + username + " does not exist.");
        }
        if (!usernameEncryptPasswordMap.get(username).equals(encrypt(password))) {
            throw new AuthException("password incorrect.");
        }
        User user = new User(username, usernameEncryptPasswordMap.get(username));
        if (!userList.contains(user)) {
            throw new AuthException("User: " + username + " does not exist.");
        }

        Authentication authentication = generateAuthentication(username);
        authenticationUserMap.put(authentication, user);
        executor.schedule(() -> {
            authenticationUserMap.remove(authentication);
        }, delay, timeUnit);
        return authentication;
    }

    @Override
    public void invalidate(Authentication authentication) throws AuthException {
        if (!authenticationUserMap.containsKey(authentication)) {
            throw new AuthException("Authentication is invalid.");
        }
        authenticationUserMap.remove(authentication);
    }

    @Override
    public boolean checkRole(Authentication authentication, Role role) throws AuthException {
        return allRoles(authentication).contains(role);
    }

    @Override
    public List<Role> allRoles(Authentication authentication) throws AuthException {
        if (!authenticationUserMap.containsKey(authentication)) {
            throw new AuthException("Authentication is invalid.");
        }
        return userRoleListMap.get(authenticationUserMap.get(authentication));
    }

    public boolean isUserExist(User user) {
        return userList.contains(user);
    }

    public boolean isRoleExist(Role role) {
        return roleList.contains(role);
    }

    public boolean isAuthenticationExist(Authentication authentication) {
        return authenticationUserMap.containsKey(authentication);
    }

    public List<Role> getUserRole(User user) {
        final List<Role> roleList = userRoleListMap.get(user);
        return userRoleListMap.get(user);
    }

    private static String encrypt(String str)  {
        String encryptPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            // 更新
            md.update(str.getBytes());
            // 获取
            byte[] bt = md.digest();
            // 转换
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bt.length; i++) {
                builder.append(Character.forDigit((bt[i] & 240) >> 4, 16));
                builder.append(Character.forDigit(bt[i] & 15, 16));
            }
            encryptPassword = builder.toString();

        }catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return encryptPassword;
    }


    private static Authentication generateAuthentication(String username) {
        return new Authentication(username + UUID.randomUUID().toString());
    }

}
