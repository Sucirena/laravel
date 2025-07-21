<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Balasan extends Model
{
    use HasFactory;

    protected $table = 'balasan';

    // Kolom yang dapat diisi
    protected $fillable = [
        'id_pasien',
        'id_diskusi',
        'isi',
    ];

    /**
     * Relasi ke model Pasien (many-to-one, balasan dibuat oleh satu pasien).
     */
    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'id_pasien');
    }

    /**
     * Relasi ke model Diskusi (many-to-one, balasan terkait dengan satu diskusi).
     */
    public function diskusi()
    {
        return $this->belongsTo(Diskusi::class, 'id_diskusi');
    }
}