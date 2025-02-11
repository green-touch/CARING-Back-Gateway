package com.caring.apigateway_service.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Getter
@Builder
@RequiredArgsConstructor
public class MemberInfo {
    private final String memberCode;
    private final String roles;
}
