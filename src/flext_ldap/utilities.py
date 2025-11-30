"""FLEXT_LDAP utilities module - Advanced enum/collection utilities."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import StrEnum
from functools import cache, wraps
from typing import Annotated, TypeVar, cast

from flext_core import FlextResult
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    ValidationError,
    validate_call,
)

T = TypeVar("T")


def _get_enum_values(enum_cls: type) -> list[str]:
    """Helper function to get enum values without generic type issues."""
    # Use getattr to safely access enum members
    members = getattr(enum_cls, "__members__", {})
    return [str(member.value) for member in members.values()]


class FlextLdapUtilities:
    """FlextLdap utilities - domain-specific implementations.

    PRINCÍPIOS:
    ───────────
    1. TypeIs (PEP 742) em vez de TypeGuard - narrowing em AMBAS branches
    2. BeforeValidator para coercion automática no Pydantic
    3. Métodos genéricos para conversão de coleções
    4. Zero TypeGuard manual no código - use estas utilities

    ARQUITETURA:
    ────────────
    - Implementações específicas do domínio LDAP
    - Não herda de FlextUtilities (diferenças intencionais de domínio)
    - Classes com mesmo nome têm comportamentos específicos do LDAP

    REFERÊNCIAS:
    ────────────
    - PEP 742: https://peps.python.org/pep-0742/
    - Pydantic Validators: https://docs.pydantic.dev/latest/concepts/validators/
    - collections.abc: https://docs.python.org/3/library/collections.abc.html
    """

    # ═══════════════════════════════════════════════════════════════════
    # NESTED CLASS: Enum Utilities
    # ═══════════════════════════════════════════════════════════════════

    class Enum:  # Different domain-specific implementation (not override)
        """Utilities para trabalhar com StrEnum de forma type-safe.

        FILOSOFIA:
        ──────────
        - TypeIs para narrowing que funciona em if/else
        - Métodos genéricos que aceitam QUALQUER StrEnum
        - Caching para performance em validações frequentes
        - Integração direta com Pydantic BeforeValidator
        """

        # ─────────────────────────────────────────────────────────────
        # TYPEIS FACTORIES: Gera funções TypeIs para qualquer StrEnum
        # ─────────────────────────────────────────────────────────────

        @staticmethod
        def is_member[E: StrEnum](enum_cls: type[E], value: object) -> bool:
            """TypeIs genérico para qualquer StrEnum.

            VANTAGEM sobre TypeGuard:
            - Narrowing funciona em AMBAS branches (if/else)
            - Type checker entende que no 'else' NÃO é E

            Exemplo:
                if FlextLdapUtilities.Enum.is_member(Status, value):
                    # value: Status
                    process_status(value)
                else:
                    # value: str (narrowed corretamente!)
                    handle_invalid(value)
            """
            if isinstance(value, enum_cls):
                return True
            if isinstance(value, str):
                try:
                    enum_cls(value)  # Try to create enum instance
                    return True
                except ValueError:
                    return False
            return False

        @staticmethod
        def is_subset[E: StrEnum](
            enum_cls: type[E],
            valid_members: frozenset[E],
            value: object,
        ) -> bool:
            """TypeIs para subset de um StrEnum.

            Exemplo:
                ACTIVE_STATES = frozenset({Status.ACTIVE, Status.PENDING})

                if FlextLdapUtilities.Enum.is_subset(Status, ACTIVE_STATES, value):
                    # value: Status (e sabemos que é ACTIVE ou PENDING)
                    process_active(value)
            """
            if isinstance(value, enum_cls):
                return value in valid_members
            if isinstance(value, str):
                try:
                    member = enum_cls(value)
                    return member in valid_members
                except ValueError:
                    return False
            return False

        # ─────────────────────────────────────────────────────────────
        # CONVERSÃO: String → StrEnum (type-safe)
        # ─────────────────────────────────────────────────────────────

        @staticmethod
        def parse[E: StrEnum](enum_cls: type[E], value: str | E) -> FlextResult[E]:
            """Converte string para StrEnum com FlextResult.

            Exemplo:
                result = FlextLdapUtilities.Enum.parse(Status, "active")
                if result.is_success:
                    status: Status = result.value
            """
            if isinstance(value, enum_cls):
                return FlextResult.ok(value)
            try:
                return FlextResult.ok(enum_cls(value))
            except ValueError:
                # Get all enum values using a helper function
                all_values = _get_enum_values(enum_cls)
                valid = ", ".join(all_values)
                return FlextResult.fail(
                    f"Invalid {getattr(enum_cls, '__name__', 'Enum')}: '{value}'. Valid: {valid}",
                )

        # ─────────────────────────────────────────────────────────────
        # PYDANTIC VALIDATORS: BeforeValidator factories
        # ─────────────────────────────────────────────────────────────

        @staticmethod
        def coerce_validator[E: StrEnum](enum_cls: type[E]) -> Callable[[object], E]:
            """Cria BeforeValidator para coerção automática no Pydantic.

            PADRÃO RECOMENDADO para campos Pydantic:

            Exemplo:
                from pydantic import BaseModel
                from typing import Annotated

                # Cria o tipo anotado uma vez
                CoercedStatus = Annotated[
                    Status,
                    BeforeValidator(FlextLdapUtilities.Enum.coerce_validator(Status))
                ]

                class MyModel(BaseModel):
                    status: CoercedStatus  # Aceita "active" ou Status.ACTIVE
            """

            def _coerce(value: object) -> E:
                if isinstance(value, enum_cls):
                    return value
                if isinstance(value, str):
                    try:
                        return enum_cls(value)
                    except ValueError:
                        pass
                msg = f"Invalid {getattr(enum_cls, '__name__', 'Enum')}: {value!r}"
                raise ValueError(msg)

            return _coerce

        # ─────────────────────────────────────────────────────────────
        # METADATA: Informações sobre StrEnums
        # ─────────────────────────────────────────────────────────────

        @staticmethod
        @cache
        def values[E: StrEnum](enum_cls: type[E]) -> frozenset[str]:
            """Retorna frozenset dos valores (cached para performance)."""
            # Get all enum values using helper function
            all_values = _get_enum_values(enum_cls)
            return frozenset(all_values)

    # ═══════════════════════════════════════════════════════════════════
    # NESTED CLASS: Collection Utilities
    # ═══════════════════════════════════════════════════════════════════

    class Collection:
        """Utilities para conversão de coleções com StrEnums.

        PADRÕES collections.abc:
        ────────────────────────
        - Sequence[E] para listas imutáveis
        - Mapping[str, E] para dicts imutáveis
        - Iterable[E] para qualquer iterável
        """

        # ─────────────────────────────────────────────────────────────
        # LIST CONVERSIONS
        # ─────────────────────────────────────────────────────────────

        @staticmethod
        def coerce_list_validator[E: StrEnum](
            enum_cls: type[E],
        ) -> Callable[[object], list[E]]:
            """BeforeValidator para lista de StrEnums.

            Exemplo:
                StatusList = Annotated[
                    list[Status],
                    BeforeValidator(FlextLdapUtilities.Collection.coerce_list_validator(Status))
                ]

                class MyModel(BaseModel):
                    statuses: StatusList  # Aceita ["active", "pending"]
            """

            def _coerce(value: object) -> list[E]:
                if not isinstance(value, (list, tuple, set, frozenset)):
                    msg = f"Expected sequence, got {type(value).__name__}"
                    raise TypeError(msg)

                result: list[E] = []
                for idx, item in enumerate(value):
                    if isinstance(item, enum_cls):
                        result.append(item)
                    elif isinstance(item, str):
                        try:
                            result.append(enum_cls(item))
                        except ValueError as e:
                            msg = f"Invalid {getattr(enum_cls, '__name__', 'Enum')} at [{idx}]: {item!r}"
                            raise ValueError(msg) from e
                    else:
                        msg = f"Expected str at [{idx}], got {type(item).__name__}"
                        raise TypeError(msg)
                return result

            return _coerce

    # ═══════════════════════════════════════════════════════════════════
    # NESTED CLASS: Args/Kwargs Automatic Parsing
    # ═══════════════════════════════════════════════════════════════════

    class Args:
        """Utilities para parsing automático de args/kwargs.

        FILOSOFIA:
        ──────────
        - Parse uma vez, use em todo lugar
        - Decorators que eliminam validação manual
        - Integração com inspect.signature para introspecção
        - ParamSpec (PEP 612) para tipagem correta de decorators

        REFERÊNCIAS:
        ────────────
        - PEP 612: https://peps.python.org/pep-0612/
        - inspect.signature: https://docs.python.org/3/library/inspect.html
        - validate_call: https://docs.pydantic.dev/latest/concepts/validation_decorator/
        """

        @staticmethod
        def validated_with_result(
            func: Callable[..., FlextResult[T]],
        ) -> Callable[..., FlextResult[T]]:
            """Decorator que converte ValidationError em FlextResult.fail().

            USE QUANDO:
            - Método retorna FlextResult
            - Quer que erros de validação virem FlextResult.fail()
            - Não quer exceptions vazando

            EXEMPLO:
                @FlextLdapUtilities.Args.validated_with_result
                def process(self, status: Status) -> FlextResult[bool]:
                    # Se status inválido → retorna FlextResult.fail()
                    # Se status válido → executa normalmente
                    return FlextResult.ok(True)
            """

            @wraps(func)
            def wrapper(*args: object, **kwargs: object) -> FlextResult[T]:
                try:
                    validated_func = validate_call(
                        config=ConfigDict(
                            arbitrary_types_allowed=True,
                            use_enum_values=False,
                        ),
                        validate_return=False,
                    )(func)
                    # Return validated result directly
                    return validated_func(*args, **kwargs)
                except ValidationError as e:
                    # Create fail result of correct type
                    fail_result = FlextResult.fail(str(e))
                    return cast("FlextResult[T]", fail_result)

            return wrapper

        @staticmethod
        def parse_kwargs[E: StrEnum](
            kwargs: Mapping[str, object],
            enum_fields: Mapping[str, type[E]],
        ) -> FlextResult[dict[str, object]]:
            """Parse kwargs convertendo campos específicos para StrEnums.

            EXEMPLO:
                result = FlextLdapUtilities.Args.parse_kwargs(
                    kwargs={"status": "active", "name": "John"},
                    enum_fields={"status": Status},
                )
                if result.is_success:
                    # result.value = {"status": Status.ACTIVE, "name": "John"}
            """
            parsed = dict(kwargs)
            errors: list[str] = []

            for field, enum_cls in enum_fields.items():
                if field in parsed:
                    value = parsed[field]
                    if isinstance(value, str):
                        try:
                            parsed[field] = enum_cls(value)
                        except ValueError:
                            # Get all enum values using helper function
                            all_values = _get_enum_values(enum_cls)
                            valid = ", ".join(all_values)
                            errors.append(f"{field}: '{value}' not in [{valid}]")

            if errors:
                return FlextResult.fail(f"Invalid values: {'; '.join(errors)}")
            return FlextResult.ok(parsed)

    # ═══════════════════════════════════════════════════════════════════
    # NESTED CLASS: Pydantic Model Initialization
    # ═══════════════════════════════════════════════════════════════════

    class Model:
        """Utilities para inicialização de modelos Pydantic.

        FILOSOFIA:
        ──────────
        - model_validate() para criar de dicts
        - Coerção automática de StrEnums
        - Merge de defaults com overrides
        - Sem code bloat de inicialização

        REFERÊNCIAS:
        ────────────
        - model_validate: https://docs.pydantic.dev/latest/api/base_model/
        - ConfigDict: https://docs.pydantic.dev/latest/api/config/
        """

        @staticmethod
        def from_dict[M: BaseModel](
            model_cls: type[M],
            data: Mapping[str, object],
            *,
            strict: bool = False,
        ) -> FlextResult[M]:
            """Cria modelo Pydantic de dict com FlextResult.

            EXEMPLO:
                result = FlextLdapUtilities.Model.from_dict(
                    UserModel,
                    {"status": "active", "name": "John"},
                )
                if result.is_success:
                    user: UserModel = result.value
            """
            try:
                instance = model_cls.model_validate(data, strict=strict)
                return FlextResult.ok(instance)
            except Exception as e:
                return FlextResult.fail(f"Model validation failed: {e}")

        @staticmethod
        def merge_defaults[M: BaseModel](
            model_cls: type[M],
            defaults: Mapping[str, object],
            overrides: Mapping[str, object],
        ) -> FlextResult[M]:
            """Merge defaults com overrides e cria modelo.

            EXEMPLO:
                DEFAULTS = {"status": Status.PENDING, "retries": 3}

                result = FlextLdapUtilities.Model.merge_defaults(
                    ConfigModel,
                    defaults=DEFAULTS,
                    overrides={"status": "active"},  # Sobrescreve
                )
                # result.value.status = Status.ACTIVE
                # result.value.retries = 3
            """
            merged = {**defaults, **overrides}
            return FlextLdapUtilities.Model.from_dict(model_cls, merged)

        @staticmethod
        def update[M: BaseModel](instance: M, **updates: object) -> FlextResult[M]:
            """Update modelo existente com novos valores.

            EXEMPLO:
                user = UserModel(name="John", status=Status.ACTIVE)
                result = FlextLdapUtilities.Model.update(user, status=Status.INACTIVE)
                if result.is_success:
                    # user.status = Status.INACTIVE
            """
            try:
                current = instance.model_dump()
                current.update(updates)
                return FlextResult.ok(instance.__class__.model_validate(current))
            except Exception as e:
                return FlextResult.fail(f"Update failed: {e}")

    # ═══════════════════════════════════════════════════════════════════
    # NESTED CLASS: Pydantic Model Configuration
    # ═══════════════════════════════════════════════════════════════════

    class Pydantic:
        """Utilities para configuração e tipos Pydantic.

        FILOSOFIA:
        ──────────
        - Annotated types pré-configurados
        - BeforeValidator factories
        - Zero boilerplate em modelos
        """

        @staticmethod
        def coerced_enum[E: StrEnum](enum_cls: type[E]) -> type:
            """Cria Annotated type com BeforeValidator para coerção automática.

            EXEMPLO:
                from typing import Annotated

                CoercedStatus = Annotated[
                    Status,
                    BeforeValidator(FlextLdapUtilities.Pydantic.coerced_enum(Status))
                ]

                class MyModel(BaseModel):
                    status: CoercedStatus  # Aceita "active" ou Status.ACTIVE
            """
            # Create a proper type alias instead of dynamic type
            return cast(
                "type",
                Annotated[
                    enum_cls,
                    BeforeValidator(FlextLdapUtilities.Enum.coerce_validator(enum_cls)),
                ],
            )
