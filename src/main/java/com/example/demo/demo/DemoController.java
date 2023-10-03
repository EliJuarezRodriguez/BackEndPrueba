package com.example.demo.demo;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@CrossOrigin("http://localhost:4200/")
public class DemoController {

    @PostMapping(value = "demo")
    public String welcome(){
        return "Welcome from secured endpoint";
    }
}

