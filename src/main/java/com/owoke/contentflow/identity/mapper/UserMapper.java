package com.owoke.contentflow.identity.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import org.mapstruct.ReportingPolicy;

import com.owoke.contentflow.identity.dto.response.RegisterResponse;
import com.owoke.contentflow.identity.dto.response.UserResponse;
import com.owoke.contentflow.identity.entity.User;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface UserMapper {

    @Mapping(target = "email", source = "email")
    @Mapping(target = "passwordHash", source = "passwordHash")
    @Mapping(target = "displayName", source = "displayName")
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "telegramUserId", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    User toUser(String email, String passwordHash, String displayName);

    RegisterResponse toRegisterResponse(User user);

    UserResponse toResponse(User user);

    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "email", source = "email")
    @Mapping(target = "displayName", source = "displayName")
    void updateProfile(String email, String displayName, @MappingTarget User user);
}
