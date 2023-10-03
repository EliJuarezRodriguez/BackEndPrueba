package com.example.demo.repository;

import com.example.demo.entity.PersonEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PersonRepository extends JpaRepository<PersonEntity,Integer> {
    Optional<PersonEntity> findByUsername(String username);

}
