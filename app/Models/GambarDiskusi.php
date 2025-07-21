<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class GambarDiskusi extends Model
{
    use HasFactory;

    protected $table = 'gambar_diskusi';

    // Kolom yang dapat diisi
    protected $fillable = [
        'id_diskusi',
        'gambar',
    ];

    /**
     * Relasi ke model Diskusi (many-to-one, gambar milik satu diskusi).
     */
    public function diskusi()
    {
        return $this->belongsTo(Diskusi::class, 'id_diskusi');
    }
        
    public $timestamps = false;
}
