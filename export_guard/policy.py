"""分级与会签策略。

清单按其中最高敏感等级决定审批要求：

- ``public`` / ``internal``：清单冻结即生效，无需会签。
- ``confidential``：需要数据所有者（data_owner）批准。
- ``restricted`` / ``secret``：数据所有者与安全值班员（security_officer）共同批准。

策略是纯数据对象，可由配置或外部策略中心替换，不持有任何运行时状态。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Mapping


class Sensitivity(IntEnum):
    """敏感等级，数值越大越敏感。"""

    PUBLIC = 10
    INTERNAL = 20
    CONFIDENTIAL = 30
    RESTRICTED = 40
    SECRET = 50

    @classmethod
    def parse(cls, raw: str) -> "Sensitivity":
        try:
            return cls[raw.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"未知敏感等级：{raw}") from exc


DATA_OWNER = "data_owner"
SECURITY_OFFICER = "security_officer"


@dataclass(frozen=True)
class ApprovalPolicy:
    """决定某敏感等级需要哪些审批角色，以及批准的有效期上限。"""

    required_roles: Mapping[Sensitivity, tuple[str, ...]] = field(
        default_factory=lambda: {
            Sensitivity.PUBLIC: (),
            Sensitivity.INTERNAL: (),
            Sensitivity.CONFIDENTIAL: (DATA_OWNER,),
            Sensitivity.RESTRICTED: (DATA_OWNER, SECURITY_OFFICER),
            Sensitivity.SECRET: (DATA_OWNER, SECURITY_OFFICER),
        }
    )
    approval_ttl_hours: Mapping[Sensitivity, int] = field(
        default_factory=lambda: {
            Sensitivity.PUBLIC: 72,
            Sensitivity.INTERNAL: 72,
            Sensitivity.CONFIDENTIAL: 48,
            Sensitivity.RESTRICTED: 24,
            Sensitivity.SECRET: 12,
        }
    )

    def roles_for(self, level: Sensitivity) -> tuple[str, ...]:
        return self.required_roles[level]

    def ttl_hours_for(self, level: Sensitivity) -> int:
        return self.approval_ttl_hours[level]

    def is_auto_approved(self, level: Sensitivity) -> bool:
        return not self.roles_for(level)
