package com.example.SecurityJWT.controller;

import com.example.SecurityJWT.dto.JoinDTO;
import com.example.SecurityJWT.dto.LoginDTO;
import com.example.SecurityJWT.service.JoinService;
import com.example.SecurityJWT.service.LoginService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {

    private final JoinService joinService;

    private final LoginService loginService;

    public JoinController(JoinService joinService, LoginService loginService) {
        this.joinService = joinService;
        this.loginService = loginService;
    }

    @PostMapping("/join")
    public String joinProcess(@RequestBody JoinDTO joinDTO) {
        joinService.joinProcess(joinDTO);
        return "ok";
    }

//    @PostMapping("/login")
//    public ResponseEntity<?> loginProcess(@RequestBody LoginDTO loginDTO) {
//        return loginService.authenticate(loginDTO);
//    }
}
