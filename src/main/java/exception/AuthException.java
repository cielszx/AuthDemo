package exception;

public class AuthException extends Exception {
    String errMsg;

    public AuthException(String errMsg) {
        this.errMsg = errMsg;
    }
    public String getMessage() {
        return errMsg;
    }

}
