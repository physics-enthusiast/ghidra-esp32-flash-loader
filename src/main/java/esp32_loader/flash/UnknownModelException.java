package esp32_loader.flash;

public class UnknownModelException extends Exception { 
    public UnknownModelException(String errorMessage) {
        super(errorMessage);
    }
}
