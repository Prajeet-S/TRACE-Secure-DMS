from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
import hashlib

from database import Base
from models import Document


class BlockchainBlock(Base):
    __tablename__ = "blockchain_blocks"

    id = Column(Integer, primary_key=True, index=True)
    block_index = Column(Integer, unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    document_id = Column(Integer, nullable=False, index=True)
    case_id = Column(Integer, nullable=False)
    file_hash = Column(String(64), nullable=False)
    action = Column(String(100), nullable=False)
    user_id = Column(Integer, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    block_hash = Column(String(64), nullable=False, unique=True, index=True)


GENESIS_HASH = "0" * 64


def calculate_block_hash(
    block_index: int,
    timestamp: str,
    document_id: int,
    case_id: int,
    file_hash: str,
    action: str,
    user_id: int,
    previous_hash: str,
) -> str:
    payload = "|".join([
        str(block_index),
        timestamp,
        str(document_id),
        str(case_id),
        file_hash,
        action,
        str(user_id),
        previous_hash,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _timestamp_value(timestamp):
    return timestamp.isoformat(timespec="microseconds")


def create_genesis_block(db):
    existing = db.query(BlockchainBlock).order_by(
        BlockchainBlock.block_index.asc()
    ).first()

    if existing:
        return existing

    timestamp = datetime.utcnow()
    block_hash = calculate_block_hash(
        0,
        _timestamp_value(timestamp),
        0,
        0,
        GENESIS_HASH,
        "GENESIS",
        0,
        GENESIS_HASH,
    )

    block = BlockchainBlock(
        block_index=0,
        timestamp=timestamp,
        document_id=0,
        case_id=0,
        file_hash=GENESIS_HASH,
        action="GENESIS",
        user_id=0,
        previous_hash=GENESIS_HASH,
        block_hash=block_hash,
    )

    db.add(block)
    db.commit()
    db.refresh(block)
    return block


def append_document_block(db, document, user_id):
    # Prevent the same document from being registered twice
    existing = db.query(BlockchainBlock).filter(
        BlockchainBlock.document_id == document.id
    ).order_by(
        BlockchainBlock.block_index.desc()
    ).first()

    if existing:
        return existing

    create_genesis_block(db)

    previous = db.query(BlockchainBlock).order_by(
        BlockchainBlock.block_index.desc()
    ).first()

    block_index = previous.block_index + 1
    timestamp = datetime.utcnow()
    previous_hash = previous.block_hash

    block_hash = calculate_block_hash(
        block_index,
        _timestamp_value(timestamp),
        document.id,
        document.case_id,
        document.file_hash,
        "DOCUMENT_UPLOADED",
        user_id,
        previous_hash,
    )

    block = BlockchainBlock(
        block_index=block_index,
        timestamp=timestamp,
        document_id=document.id,
        case_id=document.case_id,
        file_hash=document.file_hash,
        action="DOCUMENT_UPLOADED",
        user_id=user_id,
        previous_hash=previous_hash,
        block_hash=block_hash,
    )

    db.add(block)
    db.commit()
    db.refresh(block)

    return block

def ensure_blockchain_initialized(db):
    create_genesis_block(db)

    documents = db.query(Document).order_by(
        Document.uploaded_at.asc(),
        Document.id.asc(),
    ).all()

    existing_document_ids = {
        block.document_id
        for block in db.query(BlockchainBlock).filter(
            BlockchainBlock.document_id != 0
        ).all()
    }

    for document in documents:
        if document.id in existing_document_ids:
            continue

        previous = db.query(BlockchainBlock).order_by(
            BlockchainBlock.block_index.desc()
        ).first()

        block_index = previous.block_index + 1
        timestamp = document.uploaded_at or datetime.utcnow()
        previous_hash = previous.block_hash

        block_hash = calculate_block_hash(
            block_index,
            _timestamp_value(timestamp),
            document.id,
            document.case_id,
            document.file_hash,
            "DOCUMENT_UPLOADED",
            document.uploaded_by,
            previous_hash,
        )

        db.add(BlockchainBlock(
            block_index=block_index,
            timestamp=timestamp,
            document_id=document.id,
            case_id=document.case_id,
            file_hash=document.file_hash,
            action="DOCUMENT_UPLOADED",
            user_id=document.uploaded_by,
            previous_hash=previous_hash,
            block_hash=block_hash,
        ))
        db.commit()


def verify_blockchain(db):
    blocks = db.query(BlockchainBlock).order_by(
        BlockchainBlock.block_index.asc()
    ).all()

    if not blocks:
        return {
            "valid": False,
            "blocks": 0,
            "message": "Blockchain ledger is empty"
        }

    errors = []

    for expected_index, block in enumerate(blocks):
        if block.block_index != expected_index:
            errors.append(
                f"Block index gap at database id {block.id}"
            )

        expected_previous = GENESIS_HASH if expected_index == 0 else blocks[expected_index - 1].block_hash
        if block.previous_hash != expected_previous:
            errors.append(
                f"Previous hash mismatch at block {block.block_index}"
            )

        expected_hash = calculate_block_hash(
            block.block_index,
            _timestamp_value(block.timestamp),
            block.document_id,
            block.case_id,
            block.file_hash,
            block.action,
            block.user_id,
            block.previous_hash,
        )

        if block.block_hash != expected_hash:
            errors.append(
                f"Block hash mismatch at block {block.block_index}"
            )

        if expected_index == 0 and block.action != "GENESIS":
            errors.append("First block is not the genesis block")

    return {
        "valid": len(errors) == 0,
        "blocks": len(blocks),
        "latest_hash": blocks[-1].block_hash,
        "errors": errors,
    }


def get_document_block(db, document_id):
    return db.query(BlockchainBlock).filter(
        BlockchainBlock.document_id == document_id
    ).order_by(
        BlockchainBlock.block_index.desc()
    ).first()


def verify_document_block(db, document_id, current_file_hash):
    chain_status = verify_blockchain(db)
    block = get_document_block(db, document_id)

    if not block:
        return {
            "registered": False,
            "valid": False,
            "block_hash": None,
            "chain_valid": chain_status.get("valid", False),
        }

    hash_matches = block.file_hash == current_file_hash

    return {
        "registered": True,
        "valid": bool(hash_matches and chain_status.get("valid", False)),
        "block_hash": block.block_hash,
        "previous_hash": block.previous_hash,
        "block_index": block.block_index,
        "chain_valid": chain_status.get("valid", False),
        "hash_matches": hash_matches,
    }
