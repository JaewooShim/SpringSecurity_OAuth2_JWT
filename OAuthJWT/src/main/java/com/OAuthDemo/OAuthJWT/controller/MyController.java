package com.OAuthDemo.OAuthJWT.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {

    @GetMapping("/my")
    @ResponseBody
    public ResponseEntity<?> myAPI() {
        return ResponseEntity.ok("Hello my page");
    }
}
