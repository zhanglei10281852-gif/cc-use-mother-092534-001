"""分级审批策略。

敏感等级决定两件事：

1. 需要哪些角色共同批准（数据所有者、安全值班员……）；
2. 批准有效期上限与默认时长。

普通等级无需人工共同批准，由系统按同一绑定规则（清单哈希、接收方、
有效期）生成自动批准，保证领取阶段的校验路径完全一致。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Mapping

# 审批角色。
ROLE_DATA_OWNER = "data_owner"
ROLE_SECURITY_OFFICER = "security_officer"
ROLE_SYSTEM_AUTO = "system_auto"

_ROLE_NAMES = {
    ROLE_DATA_OWNER: "数据所有者",
    ROLE_SECURITY_OFFICER: "安全值班员",
    ROLE_SYSTEM_AUTO: "系统自动批准",
}


@dataclass(frozen=True)
class SensitivityRule:
    level: str
    required_roles: tuple[str, ...]
    default_validity: timedelta
    max_validity: timedelta


@dataclass(frozen=True)
class ApprovalPolicy:
    """可注入的分级策略；默认值与平台策略样例保持一致。"""

    rules: Mapping[str, SensitivityRule] = field(default_factory=dict)

    def rule_for(self, sensitivity: str) -> SensitivityRule:
        try:
            return self.rules[sensitivity]
        except KeyError as exc:  # pragma: no cover - 防御性分支
            raise ValueError(f"未知敏感等级：{sensitivity}") from exc

    def required_roles(self, sensitivity: str) -> tuple[str, ...]:
        return self.rule_for(sensitivity).required_roles

    def default_validity(self, sensitivity: str) -> timedelta:
        return self.rule_for(sensitivity).default_validity

    def clamp_validity(self, sensitivity: str, requested: timedelta | None) -> timedelta:
        rule = self.rule_for(sensitivity)
        if requested is None:
            return rule.default_validity
        if requested <= timedelta(0):
            raise ValueError("有效期必须为正")
        return min(requested, rule.max_validity)

    @staticmethod
    def role_name(role: str) -> str:
        return _ROLE_NAMES.get(role, role)


def default_policy() -> ApprovalPolicy:
    return ApprovalPolicy(
        rules={
            "normal": SensitivityRule(
                level="normal",
                required_roles=(),
                default_validity=timedelta(hours=24),
                max_validity=timedelta(hours=72),
            ),
            "confidential": SensitivityRule(
                level="confidential",
                required_roles=(ROLE_DATA_OWNER, ROLE_SECURITY_OFFICER),
                default_validity=timedelta(hours=12),
                max_validity=timedelta(hours=24),
            ),
            "restricted": SensitivityRule(
                level="restricted",
                required_roles=(ROLE_DATA_OWNER, ROLE_SECURITY_OFFICER),
                default_validity=timedelta(hours=4),
                max_validity=timedelta(hours=8),
            ),
        }
    )


# 清单条目敏感等级取最高级；数字越大越敏感。
LEVEL_ORDER = {"normal": 0, "confidential": 1, "restricted": 2}


def highest_level(levels: list[str]) -> str:
    if not levels:
        raise ValueError("清单为空，无法分级")
    return max(levels, key=lambda level: LEVEL_ORDER[level])
