package com.loginreg.loginandreg.services;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;

import com.loginreg.loginandreg.models.LoginUser;
import com.loginreg.loginandreg.models.User;
import com.loginreg.loginandreg.repositories.UserRepository;

@Service
public class UserService {
    
    @Autowired UserRepository userRepository;

    // TO-DO: Write register and login methods!
    public User register(User newUser, BindingResult result) {
        // TO-DO: Additional validations!
        // TO-DO - Reject values or register if no errors:
        
        // Reject if email is taken (present in database)
        if(userRepository.findByEmail(newUser.getEmail()).isPresent()){
            result.rejectValue("email", "Unique", "Email is taken.");
        }
        
        // Reject if password doesn't match confirmation
        if(!newUser.getPassword().equals(newUser.getConfirm())) {
            result.rejectValue("confirm", "Matches", "The Confirm Password must match Password!");
        }
        
        // Return null if result has errors
        if(result.hasErrors()){
            return null;
        }
        
        // Hash and set password, save user to database
        String hashed = BCrypt.hashpw(newUser.getPassword(), BCrypt.gensalt());
        // set password
        newUser.setPassword(hashed);

        return userRepository.save(newUser);
    }
    public User login(LoginUser newLoginObject, BindingResult result) {
        // TO-DO: Additional validations!
        Optional<User> user = userRepository.findByEmail(newLoginObject.getEmail());
        if(!user.isPresent()){
            result.rejectValue("email", "loginEmail", "Invalid credentials");
        }
        else if(!BCrypt.checkpw(newLoginObject.getPassword(), user.get().getPassword())){
            result.rejectValue("password", "logpassword", "Invalid credentials");
        }
        if(result.hasErrors()){
            return null;
        }
        return user.get();
    }

}
