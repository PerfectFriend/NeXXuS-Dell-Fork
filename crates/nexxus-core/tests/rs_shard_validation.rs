//! M-13: валидация индексов шардов при декодировании и реконструкции.
//!
//! Проверяем инварианты, на которых держится Reed-Solomon:
//!   1) индексы шардов уникальны;
//!   2) индексы идут в строго возрастающем порядке (порядок аргументов
//!      `decode`/`reconstruct` соответствует строкам обратной матрицы);
//!   3) индекс в диапазоне 0..TOTAL_SHARDS.
//!
//! Регрессия: `inverse_for_shards` строит обратную матрицу по битовой маске
//! (порядок индексов там — возрастающий), а `decode`/`reconstruct` подавали
//! шарды в порядке аргументов. Если порядок не совпадает, восстановление
//! проходило без ошибки и возвращало **неверные данные** — молчаливая
//! порча данных вместо внятной ошибки.

use nexxus_core::rs::{decode, encode, reconstruct, DATA_SHARDS, TOTAL_SHARDS};

fn payload() -> Vec<u8> {
    (0..4096u32).map(|i| (i.wrapping_mul(37) % 251) as u8).collect()
}

#[test]
fn decode_with_shuffled_indices_is_rejected_or_correct() {
    let data = payload();
    let shards = encode(&data);

    // Шарды 0..3, но в переставленном порядке: [3, 1, 2, 0]
    let shuffled: Vec<(&[u8], usize)> = vec![
        (&shards[3], 3),
        (&shards[1], 1),
        (&shards[2], 2),
        (&shards[0], 0),
    ];

    match decode(&shuffled, data.len()) {
        // После фикса: внятная ошибка (порядок/дубликаты) — либо корректные данные.
        Err(_) => {}
        Ok(out) => assert_eq!(
            out, data,
            "decode с неотсортированными индексами вернул мусор вместо данных"
        ),
    }
}

#[test]
fn decode_with_duplicate_indices_is_rejected() {
    let data = payload();
    let shards = encode(&data);
    let dup: Vec<(&[u8], usize)> = vec![
        (&shards[0], 0),
        (&shards[0], 0),
        (&shards[1], 1),
        (&shards[2], 2),
    ];
    assert!(
        decode(&dup, data.len()).is_err(),
        "дубликаты индексов шардов не отклонены"
    );
}

#[test]
fn decode_with_out_of_range_index_is_rejected() {
    let data = payload();
    let shards = encode(&data);
    let bad: Vec<(&[u8], usize)> = vec![
        (&shards[0], 0),
        (&shards[1], 1),
        (&shards[2], 2),
        (&shards[3], TOTAL_SHARDS + 7),
    ];
    assert!(
        decode(&bad, data.len()).is_err(),
        "индекс вне 0..TOTAL_SHARDS не отклонён"
    );
}

#[test]
fn reconstruct_with_shuffled_indices_is_rejected_or_correct() {
    let data = payload();
    let shards = encode(&data);
    let shuffled: Vec<(&[u8], usize)> = vec![
        (&shards[5], 5),
        (&shards[4], 4),
        (&shards[3], 3),
        (&shards[2], 2),
    ];
    match reconstruct(1, &shuffled) {
        Err(_) => {}
        Ok(s) => {
            // Если реконструкция прошла — результат обязан совпасть с оригиналом.
            let expected = &shards[1];
            assert_eq!(
                s, *expected,
                "reconstruct вернул неверный шард: данные не совпали с исходными"
            );
        }
    }
}

#[test]
fn sorted_four_shards_reconstruct_exactly() {
    // Контрольный сценарий: базовый путь не должен сломаться фиксом.
    let data = payload();
    let shards = encode(&data);
    let picked: Vec<(&[u8], usize)> = vec![
        (&shards[0], 0),
        (&shards[1], 1),
        (&shards[2], 2),
        (&shards[3], 3),
    ];
    let out = decode(&picked, data.len()).expect("decode 4 шардов");
    assert_eq!(out, data);
    assert_eq!(DATA_SHARDS, 4);
}
