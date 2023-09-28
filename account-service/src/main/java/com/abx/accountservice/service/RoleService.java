package com.abx.accountservice.service;

import com.abx.accountservice.model.RoleEntity;
import com.abx.accountservice.repository.RoleRepository;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class RoleService {

    private final RoleRepository roleRepository;

    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public RoleEntity findOrCreate(String roleName) {
        Optional<RoleEntity> optionalRoleEntity = roleRepository.findByName(roleName);
        if (optionalRoleEntity.isPresent()) {
            return optionalRoleEntity.get();
        }
        RoleEntity role = RoleEntity.Builder.newBuilder().withName(roleName).build();
        roleRepository.save(role);
        return role;
    }
}
