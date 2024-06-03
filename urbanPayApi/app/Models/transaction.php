<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class transaction extends Model
{
    use HasFactory;


    protected $fillable = [
        'user_id',
        'wallet_id',
        'transaction_id',
        'urbanPayTag',
        'account_name',
        'account_number',
        'bank_name',
        'bank_code',
        'toBank_code',
        'toBank_name',
        'toAccount_number',
        'toAccount_name',
        'amount',
        'narration',
        'reference',
        'status',
      
    ];
}
