data = '''idc.GetString	ida_bytes.get_strlit_contents	
idc.GetRegValue	idc.get_reg_value	
idc.LocByName	idc.get_name_ea_simple	
idc.AddBpt	idc.add_bpt	
idc.Compile(file)	idc.CompileEx(file, 1)	
idc.CompileEx(input, is_file)	idc.compile_idc_file(input) if is_file else compile_idc_text(input)	
idc.OpOffset(ea, base)	idc.op_plain_offset(ea, -1, base)	
idc.OpNum(ea)	idc.op_num(ea, -1)	
idc.OpChar(ea)	idc.op_chr(ea, -1)	
idc.OpSegment(ea)	idc.op_seg(ea, -1)	
idc.OpDec(ea)	idc.op_dec(ea, -1)	
idc.OpAlt1(ea, str)	idc.op_man(ea, 0, str)	
idc.OpAlt2(ea, str)	idc.op_man(ea, 1, str)	
idc.StringStp(x)	idc.set_inf_attr(INF_STRLIT_BREAK, x)	
idc.LowVoids(x)	idc.set_inf_attr(INF_LOW_OFF, x)	
idc.HighVoids(x)	idc.set_inf_attr(INF_HIGH_OFF, x)	
idc.TailDepth(x)	idc.set_inf_attr(INF_MAXREF, x)	
idc.Analysis(x)	idc.set_flag(INF_GENFLAGS, INFFL_AUTO, x)	
idc.Comments(x)	idc.set_flag(INF_CMTFLAG, SW_ALLCMT, x)	
idc.Voids(x)	idc.set_flag(INF_OUTFLAGS, OFLG_SHOW_VOID, x)	
idc.XrefShow(x)	idc.set_inf_attr(INF_XREFNUM, x)	
idc.Indent(x)	idc.set_inf_attr(INF_INDENT, x)	
idc.CmtIndent(x)	idc.set_inf_attr(INF_COMMENT, x)	
idc.AutoShow(x)	idc.set_flag(INF_OUTFLAGS, OFLG_SHOW_AUTO, x)	
idc.MinEA()	ida_ida.inf_get_min_ea()	
idc.MaxEA()	ida_ida.inf_get_max_ea()	
idc.StartEA()	ida_ida.inf_get_min_ea()	
idc.BeginEA()	ida_ida.inf_get_min_ea()	
idc.set_start_cs(x)	idc.set_inf_attr(INF_START_CS, x)	
idc.set_start_ip(x)	idc.set_inf_attr(INF_START_IP, x)	
idc.auto_make_code(x)	idc.auto_mark_range(x, (x)+1, AU_CODE);	
idc.AddConst(enum_id, name, value)	idc.add_enum_member(enum_id, name, value, -1)	
idc.AddStruc(index, name)	idc.add_struc(index, name, 0)	
idc.AddUnion(index, name)	idc.add_struc(index, name, 1)	
idc.OpStroff(ea, n, strid)	idc.op_stroff(ea, n, strid, 0)	
idc.OpEnum(ea, n, enumid)	idc.op_enum(ea, n, enumid, 0)	
idc.DelConst(id, v, mask)	idc.del_enum_member(id, v, 0, mask)	
idc.GetConst(id, v, mask)	idc.get_enum_member(id, v, 0, mask)	
idc.AnalyseRange	idc.plan_and_wait	
idc.AnalyseArea	idc.plan_and_wait	
idc.AnalyzeArea	idc.plan_and_wait	
idc.MakeStruct(ea, name)	idc.create_struct(ea, -1, name)	
idc.Name(ea)	idc.get_name(ea, ida_name.GN_VISIBLE)	
idc.GetTrueName	ida_name.get_ea_name	
idc.MakeName(ea, name)	idc.set_name(ea, name, SN_CHECK)	
idc.GetFrame(ea)	idc.get_func_attr(ea, FUNCATTR_FRAME)	
idc.GetFrameLvarSize(ea)	idc.get_func_attr(ea, FUNCATTR_FRSIZE)	
idc.GetFrameRegsSize(ea)	idc.get_func_attr(ea, FUNCATTR_FRREGS)	
idc.GetFrameArgsSize(ea)	idc.get_func_attr(ea, FUNCATTR_ARGSIZE)	
idc.GetFunctionFlags(ea)	idc.get_func_attr(ea, FUNCATTR_FLAGS)	
idc.SetFunctionFlags(ea, flags)	idc.set_func_attr(ea, FUNCATTR_FLAGS, flags)	
idc.SegCreate	idc.AddSeg	
idc.SegDelete	idc.del_segm	
idc.SegBounds	idc.set_segment_bounds	
idc.SegRename	idc.set_segm_name	
idc.SegClass	idc.set_segm_class	
idc.SegAddrng	idc.set_segm_addressing	
idc.SegDefReg	idc.set_default_sreg_value	
idc.Comment(ea)	idc.get_cmt(ea, 0)	
idc.RptCmt(ea)	idc.get_cmt(ea, 1)	
idc.MakeByte(ea)	ida_bytes.create_data(ea, FF_BYTE, 1, ida_idaapi.BADADDR)	
idc.MakeWord(ea)	ida_bytes.create_data(ea, FF_WORD, 2, ida_idaapi.BADADDR)	
idc.MakeDword(ea)	ida_bytes.create_data(ea, FF_DWORD, 4, ida_idaapi.BADADDR)	
idc.MakeQword(ea)	ida_bytes.create_data(ea, FF_QWORD, 8, ida_idaapi.BADADDR)	
idc.MakeOword(ea)	ida_bytes.create_data(ea, FF_OWORD, 16, ida_idaapi.BADADDR)	
idc.MakeYword(ea)	ida_bytes.create_data(ea, FF_YWORD, 32, ida_idaapi.BADADDR)	
idc.MakeFloat(ea)	ida_bytes.create_data(ea, FF_FLOAT, 4, ida_idaapi.BADADDR)	
idc.MakeDouble(ea)	ida_bytes.create_data(ea, FF_DOUBLE, 8, ida_idaapi.BADADDR)	
idc.MakePackReal(ea)	ida_bytes.create_data(ea, FF_PACKREAL, 10, ida_idaapi.BADADDR)	
idc.MakeTbyte(ea)	ida_bytes.create_data(ea, FF_TBYTE, 10, ida_idaapi.BADADDR)	
idc.MakeCustomData(ea, size, dtid, fid)	ida_bytes.create_data(ea, FF_CUSTOM, size, dtid|((fid)<<16))	
idc.SetReg(ea, reg, value)	idc.split_sreg_range(ea, reg, value, SR_user)	
idc.SegByName	idc.selector_by_name	
idc.MK_FP	idc.to_ea	
idc.toEA	idc.to_ea	
idc.MakeCode	idc.create_insn	
idc.MakeNameEx	idc.set_name	
idc.MakeArray	idc.make_array	
idc.MakeData	ida_bytes.create_data	
idc.GetRegValue	idc.get_reg_value	
idc.SetRegValue	idc.set_reg_value	
idc.Byte	idc.get_wide_byte	
idc.Word	idc.get_wide_word	
idc.Dword	idc.get_wide_dword	
idc.Qword	idc.get_qword	
idc.LocByName	idc.get_name_ea_simple	
idc.ScreenEA	idc.get_screen_ea	
idc.GetTinfo	idc.get_tinfo	
idc.OpChr	idc.op_chr	
idc.OpSeg	idc.op_seg	
idc.OpNumber	idc.op_num	
idc.OpDecimal	idc.op_dec	
idc.OpOctal	idc.op_oct	
idc.OpBinary	idc.op_bin	
idc.OpHex	idc.op_hex	
idc.OpAlt	idc.op_man	
idc.OpSign	idc.toggle_sign	
idc.OpNot	idc.toggle_bnot	
idc.OpEnumEx	idc.op_enum	
idc.OpStroffEx	idc.op_stroff	
idc.OpStkvar	idc.op_stkvar	
idc.OpFloat	idc.op_flt	
idc.OpOffEx	idc.op_offset	
idc.OpOff	idc.op_plain_offset	
idc.MakeStructEx	idc.create_struct	
idc.Jump	ida_kernwin.jumpto	
idc.GenerateFile	idc.gen_file	
idc.GenFuncGdl	idc.gen_flow_graph	
idc.GenCallGdl	idc.gen_simple_call_chart	
idc.IdbByte	ida_bytes.get_db_byte	
idc.DbgByte	idc.read_dbg_byte	
idc.DbgWord	idc.read_dbg_word	
idc.DbgDword	idc.read_dbg_dword	
idc.DbgQword	idc.read_dbg_qword	
idc.DbgRead	idc.read_dbg_memory	
idc.DbgWrite	idc.write_dbg_memory	
idc.PatchDbgByte	idc.patch_dbg_byte	
idc.PatchByte	ida_bytes.patch_byte	
idc.PatchWord	ida_bytes.patch_word	
idc.PatchDword	ida_bytes.patch_dword	
idc.PatchQword	ida_bytes.patch_qword	
idc.SetProcessorType	ida_idp.set_processor_type	
idc.SetTargetAssembler	ida_idp.set_target_assembler	
idc.Batch	idc.batch	
idc.SetSegDefReg	idc.set_default_sreg_value	
idc.GetReg	idc.get_sreg	
idc.SetRegEx	idc.split_sreg_range	
idc.WriteMap(path)	idc.gen_file(OFILE_MAP, path, 0, BADADDR, GENFLG_MAPSEG|GENFLG_MAPNAME)	
idc.WriteTxt(path, ea1, ea2)	idc.gen_file(OFILE_ASM, path, ea1, ea2, 0)	
idc.WriteExe(path)	idc.gen_file(OFILE_EXE, path, 0, BADADDR, 0)	
idc.AskStr(defval, prompt)	ida_kernwin.ask_str(defval, 0, prompt)	
idc.AskFile	ida_kernwin.ask_file	
idc.AskAddr	ida_kernwin.ask_addr	
idc.AskLong	ida_kernwin.ask_long	
idc.AskSeg	ida_kernwin.ask_seg	
idc.AskIdent(defval, prompt)	ida_kernwin.ask_str(defval, ida_kernwin.HIST_IDENT, prompt)	
idc.AskYN	ida_kernwin.ask_yn	
idc.DeleteAll	idc.delete_all_segments	
idc.AddSegEx	idc.add_segm_ex	
idc.SetSegBounds	idc.set_segment_bounds	
idc.RenameSeg	idc.set_segm_name	
idc.SetSegClass	idc.set_segm_class	
idc.SetSegAddressing	idc.set_segm_addressing	
idc.SetSegmentAttr	idc.set_segm_attr	
idc.GetSegmentAttr	idc.get_segm_attr	
idc.SetStorageType	ida_bytes.change_storage_type	
idc.MoveSegm	idc.move_segm	
idc.RebaseProgram	ida_segment.rebase_program	
idc.GetNsecStamp	idc.get_nsec_stamp	
idc.LocByNameEx	ida_name.get_name_ea	
idc.SegByBase	idc.get_segm_by_sel	
idc.GetCurrentLine	idc.get_curline	
idc.SelStart	idc.read_selection_start	
idc.SelEnd	idc.read_selection_end	
idc.FirstSeg	idc.get_first_seg	
idc.NextSeg	idc.get_next_seg	
idc.SegName	idc.get_segm_name	
idc.CommentEx	ida_bytes.get_cmt	
idc.AltOp	ida_bytes.get_forced_operand	
idc.GetDisasmEx	idc.generate_disasm_line	
idc.GetMnem	idc.print_insn_mnem	
idc.GetOpType	idc.get_operand_type	
idc.GetOperandValue	idc.get_operand_value	
idc.DecodeInstruction	ida_ua.decode_insn	
idc.NextAddr	ida_bytes.next_addr	
idc.PrevAddr	ida_bytes.prev_addr	
idc.NextNotTail	ida_bytes.next_not_tail	
idc.PrevNotTail	ida_bytes.prev_not_tail	
idc.ItemHead	ida_bytes.get_item_head	
idc.ItemEnd	ida_bytes.get_item_end	
idc.ItemSize	idc.get_item_size	
idc.AnalyzeRange	idc.plan_and_wait	
idc.ExecIDC	idc.exec_idc	
idc.Eval	idc.eval_idc	
idc.Exit	ida_pro.qexit	
idc.FindVoid	ida_search.find_suspop	
idc.FindCode	ida_search.find_code	
idc.FindData	ida_search.find_data	
idc.FindUnexplored	ida_search.find_unknown	
idc.FindExplored	ida_search.find_defined	
idc.FindImmediate	ida_search.find_imm	
idc.AddCodeXref	ida_xref.add_cref	
idc.DelCodeXref	ida_xref.del_cref	
idc.Rfirst	ida_xref.get_first_cref_from	
idc.RfirstB	ida_xref.get_first_cref_to	
idc.Rnext	ida_xref.get_next_cref_from	
idc.RnextB	ida_xref.get_next_cref_to	
idc.Rfirst0	ida_xref.get_first_fcref_from	
idc.RfirstB0	ida_xref.get_first_fcref_to	
idc.Rnext0	ida_xref.get_next_fcref_from	
idc.RnextB0	ida_xref.get_next_fcref_to	
idc.Dfirst	ida_xref.get_first_dref_from	
idc.Dnext	ida_xref.get_next_dref_from	
idc.DfirstB	ida_xref.get_first_dref_to	
idc.DnextB	ida_xref.get_next_dref_to	
idc.XrefType	idc.get_xref_type	
idc.AutoUnmark	ida_auto.auto_unmark	
idc.AutoMark2	ida_auto.auto_mark_range	
idc.SetSelector	ida_segment.set_selector	
idc.AskSelector	idc.sel2para	
idc.ask_selector	idc.sel2para	
idc.FindSelector	idc.find_selector	
idc.DelSelector	ida_segment.del_selector	
idc.MakeFunction	ida_funcs.add_func	
idc.DelFunction	ida_funcs.del_func	
idc.SetFunctionEnd	ida_funcs.set_func_end	
idc.NextFunction	idc.get_next_func	
idc.PrevFunction	idc.get_prev_func	
idc.GetFunctionAttr	idc.get_func_attr	
idc.SetFunctionAttr	idc.set_func_attr	
idc.GetFunctionName	idc.get_func_name	
idc.GetFunctionCmt	idc.get_func_cmt	
idc.SetFunctionCmt	idc.set_func_cmt	
idc.ChooseFunction	idc.choose_func	
idc.GetFuncOffset	idc.get_func_off_str	
idc.MakeLocal	idc.define_local_var	
idc.FindFuncEnd	idc.find_func_end	
idc.GetFrameSize	idc.get_frame_size	
idc.MakeFrame	idc.set_frame_size	
idc.GetSpd	idc.get_spd	
idc.GetSpDiff	idc.get_sp_delta	
idc.DelStkPnt	idc.del_stkpnt	
idc.AddAutoStkPnt2	idc.add_auto_stkpnt	
idc.RecalcSpd	ida_frame.recalc_spd	
idc.GetMinSpd	idc.get_min_spd_ea	
idc.GetFchunkAttr	idc.get_fchunk_attr	
idc.SetFchunkAttr	idc.set_fchunk_attr	
idc.GetFchunkReferer	ida_funcs.get_fchunk_referer	
idc.NextFchunk	idc.get_next_fchunk	
idc.PrevFchunk	idc.get_prev_fchunk	
idc.AppendFchunk	idc.append_func_tail	
idc.RemoveFchunk	idc.remove_fchunk	
idc.SetFchunkOwner	idc.set_tail_owner	
idc.FirstFuncFchunk	idc.first_func_chunk	
idc.NextFuncFchunk	idc.next_func_chunk	
idc.GetEntryPointQty	ida_entry.get_entry_qty	
idc.AddEntryPoint	ida_entry.add_entry	
idc.GetEntryName	ida_entry.get_entry_name	
idc.GetEntryOrdinal	ida_entry.get_entry_ordinal	
idc.GetEntryPoint	ida_entry.get_entry	
idc.RenameEntryPoint	ida_entry.rename_entry	
idc.GetNextFixupEA	ida_fixup.get_next_fixup_ea	
idc.GetPrevFixupEA	ida_fixup.get_prev_fixup_ea	
idc.GetFixupTgtType	idc.get_fixup_target_type	
idc.GetFixupTgtFlags	idc.get_fixup_target_flags	
idc.GetFixupTgtSel	idc.get_fixup_target_sel	
idc.GetFixupTgtOff	idc.get_fixup_target_off	
idc.GetFixupTgtDispl	idc.get_fixup_target_dis	
idc.SetFixup	idc.set_fixup	
idc.DelFixup	ida_fixup.del_fixup	
idc.MarkPosition	idc.put_bookmark	
idc.GetMarkedPos	idc.get_bookmark	
idc.GetMarkComment	idc.get_bookmark_desc	
idc.GetStrucQty	ida_struct.get_struc_qty	
idc.GetFirstStrucIdx	ida_struct.get_first_struc_idx	
idc.GetLastStrucIdx	ida_struct.get_last_struc_idx	
idc.GetNextStrucIdx	ida_struct.get_next_struc_idx	
idc.GetPrevStrucIdx	ida_struct.get_prev_struc_idx	
idc.GetStrucIdx	ida_struct.get_struc_idx	
idc.GetStrucId	ida_struct.get_struc_by_idx	
idc.GetStrucIdByName	ida_struct.get_struc_id	
idc.GetStrucName	ida_struct.get_struc_name	
idc.GetStrucComment	ida_struct.get_struc_cmt	
idc.GetStrucSize	ida_struct.get_struc_size	
idc.GetMemberQty	idc.get_member_qty	
idc.GetStrucPrevOff	idc.get_prev_offset	
idc.GetStrucNextOff	idc.get_next_offset	
idc.GetFirstMember	idc.get_first_member	
idc.GetLastMember	idc.get_last_member	
idc.GetMemberOffset	idc.get_member_offset	
idc.GetMemberName	idc.get_member_name	
idc.GetMemberComment	idc.get_member_cmt	
idc.GetMemberSize	idc.get_member_size	
idc.GetMemberFlag	idc.get_member_flag	
idc.GetMemberStrId	idc.get_member_strid	
idc.GetMemberId	idc.get_member_id	
idc.AddStrucEx	idc.add_struc	
idc.IsUnion	idc.is_union	
idc.DelStruc	idc.del_struc	
idc.SetStrucIdx	idc.set_struc_idx	
idc.SetStrucName	ida_struct.set_struc_name	
idc.SetStrucComment	ida_struct.set_struc_cmt	
idc.SetStrucAlign	idc.set_struc_align	
idc.AddStrucMember	idc.add_struc_member	
idc.DelStrucMember	idc.del_struc_member	
idc.SetMemberName	idc.set_member_name	
idc.SetMemberType	idc.set_member_type	
idc.SetMemberComment	idc.set_member_cmt	
idc.ExpandStruc	idc.expand_struc	
idc.SetLineNumber	ida_nalt.set_source_linnum	
idc.GetLineNumber	ida_nalt.get_source_linnum	
idc.DelLineNumber	ida_nalt.del_source_linnum	
idc.AddSourceFile	ida_lines.add_sourcefile	
idc.GetSourceFile	ida_lines.get_sourcefile	
idc.DelSourceFile	ida_lines.del_sourcefile	
idc.CreateArray	idc.create_array	
idc.GetArrayId	idc.get_array_id	
idc.RenameArray	idc.rename_array	
idc.DeleteArray	idc.delete_array	
idc.SetArrayLong	idc.set_array_long	
idc.SetArrayString	idc.set_array_string	
idc.GetArrayElement	idc.get_array_element	
idc.DelArrayElement	idc.del_array_element	
idc.GetFirstIndex	idc.get_first_index	
idc.GetNextIndex	idc.get_next_index	
idc.GetLastIndex	idc.get_last_index	
idc.GetPrevIndex	idc.get_prev_index	
idc.SetHashLong	idc.set_hash_long	
idc.SetHashString	idc.set_hash_string	
idc.GetHashLong	idc.get_hash_long	
idc.GetHashString	idc.get_hash_string	
idc.DelHashElement	idc.del_hash_string	
idc.GetFirstHashKey	idc.get_first_hash_key	
idc.GetNextHashKey	idc.get_next_hash_key	
idc.GetLastHashKey	idc.get_last_hash_key	
idc.GetPrevHashKey	idc.get_prev_hash_key	
idc.GetEnumQty	ida_enum.get_enum_qty	
idc.GetnEnum	ida_enum.getn_enum	
idc.GetEnumIdx	ida_enum.get_enum_idx	
idc.GetEnum	ida_enum.get_enum	
idc.GetEnumName	ida_enum.get_enum_name	
idc.GetEnumCmt	ida_enum.get_enum_cmt	
idc.GetEnumSize	ida_enum.get_enum_size	
idc.GetEnumWidth	ida_enum.get_enum_width	
idc.GetEnumFlag	ida_enum.get_enum_flag	
idc.GetConstByName	ida_enum.get_enum_member_by_name	
idc.GetConstValue	ida_enum.get_enum_member_value	
idc.GetConstBmask	ida_enum.get_enum_member_bmask	
idc.GetConstEnum	ida_enum.get_enum_member_enum	
idc.GetConstEx	idc.get_enum_member	
idc.GetFirstBmask	ida_enum.get_first_bmask	
idc.GetLastBmask	ida_enum.get_last_bmask	
idc.GetNextBmask	ida_enum.get_next_bmask	
idc.GetPrevBmask	ida_enum.get_prev_bmask	
idc.GetFirstConst	idc.get_first_enum_member	
idc.GetLastConst	idc.get_last_enum_member	
idc.GetNextConst	idc.get_next_enum_member	
idc.GetPrevConst	idc.get_prev_enum_member	
idc.GetConstName	idc.get_enum_member_name	
idc.GetConstCmt	idc.get_enum_member_cmt	
idc.AddEnum	idc.add_enum	
idc.DelEnum	ida_enum.del_enum	
idc.SetEnumIdx	ida_enum.set_enum_idx	
idc.SetEnumName	ida_enum.set_enum_name	
idc.SetEnumCmt	ida_enum.set_enum_cmt	
idc.SetEnumFlag	ida_enum.set_enum_flag	
idc.SetEnumWidth	ida_enum.set_enum_width	
idc.SetEnumBf	ida_enum.set_enum_bf	
idc.AddConstEx	idc.add_enum_member	
idc.DelConstEx	idc.del_enum_member	
idc.SetConstName	ida_enum.set_enum_member_name	
idc.SetConstCmt	ida_enum.set_enum_member_cmt	
idc.IsBitfield	ida_enum.is_bf	
idc.SetBmaskName	idc.set_bmask_name	
idc.GetBmaskName	idc.get_bmask_name	
idc.SetBmaskCmt	idc.set_bmask_cmt	
idc.GetBmaskCmt	idc.get_bmask_cmt	
idc.GetLongPrm	idc.get_inf_attr	
idc.GetShortPrm	idc.get_inf_attr	
idc.GetCharPrm	idc.get_inf_attr	
idc.SetLongPrm	idc.set_inf_attr	
idc.SetShortPrm	idc.set_inf_attr	
idc.SetCharPrm	idc.set_inf_attr	
idc.ChangeConfig	idc.process_config_line	
idc.AddHotkey	ida_kernwin.add_idc_hotkey	
idc.DelHotkey	ida_kernwin.del_idc_hotkey	
idc.GetInputFile	ida_nalt.get_root_filename	
idc.GetInputFilePath	ida_nalt.get_input_file_path	
idc.SetInputFilePath	ida_nalt.set_root_filename	
idc.GetInputFileSize	idc.retrieve_input_file_size	
idc.Exec	idc.call_system	
idc.Sleep	idc.qsleep	
idc.GetIdaDirectory	idc.idadir	
idc.GetIdbPath	idc.get_idb_path	
idc.GetInputMD5	ida_nalt.retrieve_input_file_md5	
idc.OpHigh	idc.op_offset_high16	
idc.MakeAlign	ida_bytes.create_align	
idc.Demangle	idc.demangle_name	
idc.SetManualInsn	ida_bytes.set_manual_insn	
idc.GetManualInsn	ida_bytes.get_manual_insn	
idc.SetArrayFormat	idc.set_array_params	
idc.LoadTil	idc.add_default_til	
idc.Til2Idb	idc.import_type	
idc.GetMaxLocalType	idc.get_ordinal_qty	
idc.SetLocalType	idc.set_local_type	
idc.GetLocalTinfo	idc.get_local_tinfo	
idc.GetLocalTypeName	idc.get_numbered_type_name	
idc.PrintLocalTypes	idc.print_decls	
idc.SetStatus	ida_auto.set_ida_state	
idc.Refresh	ida_kernwin.refresh_idaview_anyway	
idc.RefreshLists	ida_kernwin.refresh_choosers	
idc.RunPlugin	ida_loader.load_and_run_plugin	
idc.ApplySig	ida_funcs.plan_to_apply_idasgn	
idc.ApplyType	idc.apply_type	
idc.GetStringType	idc.get_str_type	
idc.GetOriginalByte	ida_bytes.get_original_byte	
idc.HideRange	ida_bytes.add_hidden_range	
idc.SetHiddenRange	idc.update_hidden_range	
idc.DelHiddenRange	ida_bytes.del_hidden_range	
idc.DelHiddenArea	ida_bytes.del_hidden_range	
idc.GetType	idc.get_type	
idc.GuessType	idc.guess_type	
idc.ParseType	idc.parse_decl	
idc.ParseTypes	idc.parse_decls	
idc.GetColor	idc.get_color	
idc.SetColor	idc.set_color	
idc.GetBptQty	ida_dbg.get_bpt_qty	
idc.GetBptEA	idc.get_bpt_ea	
idc.GetBptAttr	idc.get_bpt_attr	
idc.SetBptAttr	idc.set_bpt_attr	
idc.SetBptCndEx	idc.set_bpt_cond	
idc.SetBptCnd	idc.set_bpt_cond	
idc.AddBptEx	ida_dbg.add_bpt	
idc.AddBpt	ida_dbg.add_bpt	
idc.DelBpt	ida_dbg.del_bpt	
idc.EnableBpt	ida_dbg.enable_bpt	
idc.CheckBpt	ida_dbg.check_bpt	
idc.LoadDebugger	ida_dbg.load_debugger	
idc.StartDebugger	ida_dbg.start_process	
idc.StopDebugger	ida_dbg.exit_process	
idc.PauseProcess	ida_dbg.suspend_process	
idc.GetProcessQty()	ida_dbg.get_processes().size	
idc.GetProcessPid(idx)	ida_dbg.get_processes()[idx].pid	
idc.GetProcessName(idx)	ida_dbg.get_processes()[idx].name	
idc.AttachProcess	ida_dbg.attach_process	
idc.DetachProcess	ida_dbg.detach_process	
idc.GetThreadQty	ida_dbg.get_thread_qty	
idc.GetThreadId	ida_dbg.getn_thread	
idc.GetCurrentThreadId	ida_dbg.get_current_thread	
idc.SelectThread	ida_dbg.select_thread	
idc.SuspendThread	ida_dbg.suspend_thread	
idc.ResumeThread	ida_dbg.resume_thread	
idc.GetFirstModule	idc.get_first_module	
idc.GetNextModule	idc.get_next_module	
idc.GetModuleName	idc.get_module_name	
idc.GetModuleSize	idc.get_module_size	
idc.StepInto	ida_dbg.step_into	
idc.StepOver	ida_dbg.step_over	
idc.RunTo	ida_dbg.run_to	
idc.StepUntilRet	ida_dbg.step_until_ret	
idc.GetDebuggerEvent	ida_dbg.wait_for_next_event	
idc.GetProcessState	ida_dbg.get_process_state	
idc.SetDebuggerOptions	ida_dbg.set_debugger_options	
idc.SetRemoteDebugger	ida_dbg.set_remote_debugger	
idc.GetDebuggerEventCondition	ida_dbg.get_debugger_event_cond	
idc.SetDebuggerEventCondition	ida_dbg.set_debugger_event_cond	
idc.GetEventId	idc.get_event_id	
idc.GetEventPid	idc.get_event_pid	
idc.GetEventTid	idc.get_event_tid	
idc.GetEventEa	idc.get_event_ea	
idc.IsEventHandled	idc.is_event_handled	
idc.GetEventModuleName	idc.get_event_module_name	
idc.GetEventModuleBase	idc.get_event_module_base	
idc.GetEventModuleSize	idc.get_event_module_size	
idc.GetEventExitCode	idc.get_event_exit_code	
idc.GetEventInfo	idc.get_event_info	
idc.GetEventBptHardwareEa	idc.get_event_bpt_hea	
idc.GetEventExceptionCode	idc.get_event_exc_code	
idc.GetEventExceptionEa	idc.get_event_exc_ea	
idc.GetEventExceptionInfo	idc.get_event_exc_info	
idc.CanExceptionContinue	idc.can_exc_continue	
idc.RefreshDebuggerMemory	ida_dbg.refresh_debugger_memory	
idc.TakeMemorySnapshot	ida_segment.take_memory_snapshot	
idc.EnableTracing	idc.enable_tracing	
idc.GetStepTraceOptions	ida_dbg.get_step_trace_options	
idc.SetStepTraceOptions	ida_dbg.set_step_trace_options	
idc.DefineException	ida_dbg.define_exception	
idc.BeginTypeUpdating	ida_typeinf.begin_type_updating	
idc.EndTypeUpdating	ida_typeinf.end_type_updating	
idc.begin_type_updating	ida_typeinf.begin_type_updating	
idc.end_type_updating	ida_typeinf.end_type_updating	
idc.ValidateNames	idc.validate_idb_names	
idc.SegAlign(ea, alignment)	idc.set_segm_attr(ea, SEGATTR_ALIGN, alignment)	
idc.SegComb(ea, comb)	idc.set_segm_attr(ea, SEGATTR_COMB, comb)	
idc.MakeComm(ea, cmt)	idc.set_cmt(ea, cmt, 0)	
idc.MakeRptCmt(ea, cmt)	idc.set_cmt(ea, cmt, 1)	
idc.MakeUnkn	ida_bytes.del_items	
idc.MakeUnknown	ida_bytes.del_items	
idc.LineA(ea, n)	ida_lines.get_extra_cmt(ea, E_PREV + (n))	
idc.LineB(ea, n)	ida_lines.get_extra_cmt(ea, E_NEXT + (n))	
idc.ExtLinA(ea, n, line)	ida_lines.update_extra_cmt(ea, E_PREV + (n), line)	
idc.ExtLinB(ea, n, line)	ida_lines.update_extra_cmt(ea, E_NEXT + (n), line)	
idc.DelExtLnA(ea, n)	ida_lines.del_extra_cmt(ea, E_PREV + (n))	
idc.DelExtLnB(ea, n)	ida_lines.del_extra_cmt(ea, E_NEXT + (n))	
idc.SetSpDiff	ida_frame.add_user_stkpnt	
idc.AddUserStkPnt	ida_frame.add_user_stkpnt	
idc.NameEx(From, ea)	idc.get_name(ea, ida_name.GN_VISIBLE | calc_gtn_flags(From, ea))	
idc.GetTrueNameEx(From, ea)	idc.get_name(ea, calc_gtn_flags(From, ea))	
idc.Message	ida_kernwin.msg	
idc.UMessage	ida_kernwin.msg	
idc.DelSeg	ida_segment.del_segm	
idc.Wait	ida_auto.auto_wait	
idc.LoadTraceFile	ida_dbg.load_trace_file	
idc.SaveTraceFile	ida_dbg.save_trace_file	
idc.CheckTraceFile	ida_dbg.is_valid_trace_file	
idc.DiffTraceFile	ida_dbg.diff_trace_file	
idc.SetTraceDesc	ida_dbg.get_trace_file_desc	
idc.GetTraceDesc	ida_dbg.set_trace_file_desc	
idc.GetMaxTev	ida_dbg.get_tev_qty	
idc.GetTevEa	ida_dbg.get_tev_ea	
idc.GetTevType	ida_dbg.get_tev_type	
idc.GetTevTid	ida_dbg.get_tev_tid	
idc.GetTevRegVal	ida_dbg.get_tev_reg	
idc.GetTevRegMemQty	ida_dbg.get_tev_mem_qty	
idc.GetTevRegMem	ida_dbg.get_tev_mem	
idc.GetTevRegMemEa	ida_dbg.get_tev_mem_ea	
idc.GetTevCallee	ida_dbg.get_call_tev_callee	
idc.GetTevReturn	ida_dbg.get_ret_tev_return	
idc.GetBptTevEa	ida_dbg.get_bpt_tev_ea	
idc.ArmForceBLJump	idc.force_bl_jump	
idc.ArmForceBLCall	idc.force_bl_call	
idc.BochsCommand	idc.send_dbg_command	
idc.SendDbgCommand	idc.send_dbg_command	
idc.SendGDBMonitor	idc.send_dbg_command	
idc.WinDbgCommand	idc.send_dbg_command	
idc.SetAppcallOptions(x)	idc.set_inf_attr(INF_APPCALL_OPTIONS, x)	
idc.GetAppcallOptions()	idc.get_inf_attr(INF_APPCALL_OPTIONS)	
idc.AF2_ANORET	ida_ida.AF_ANORET	
idc.AF2_CHKUNI	ida_ida.AF_CHKUNI	
idc.AF2_DATOFF	ida_ida.AF_DATOFF	
idc.AF2_DOCODE	ida_ida.AF_DOCODE	
idc.AF2_DODATA	ida_ida.AF_DODATA	
idc.AF2_FTAIL	ida_ida.AF_FTAIL	
idc.AF2_HFLIRT	ida_ida.AF_HFLIRT	
idc.AF2_JUMPTBL	ida_ida.AF_JUMPTBL	
idc.AF2_PURDAT	ida_ida.AF_PURDAT	
idc.AF2_REGARG	ida_ida.AF_REGARG	
idc.AF2_SIGCMT	ida_ida.AF_SIGCMT	
idc.AF2_SIGMLT	ida_ida.AF_SIGMLT	
idc.AF2_STKARG	ida_ida.AF_STKARG	
idc.AF2_TRFUNC	ida_ida.AF_TRFUNC	
idc.AF2_VERSP	ida_ida.AF_VERSP	
idc.AF_ASCII	ida_ida.AF_STRLIT	
idc.ASCF_AUTO	ida_ida.STRF_AUTO	
idc.ASCF_COMMENT	ida_ida.STRF_COMMENT	
idc.ASCF_GEN	ida_ida.STRF_GEN	
idc.ASCF_SAVECASE	ida_ida.STRF_SAVECASE	
idc.ASCF_SERIAL	ida_ida.STRF_SERIAL	
idc.ASCSTR_C	ida_nalt.STRTYPE_C	
idc.ASCSTR_LEN2	ida_nalt.STRTYPE_LEN2	
idc.ASCSTR_LEN4	ida_nalt.STRTYPE_LEN4	
idc.ASCSTR_PASCAL	ida_nalt.STRTYPE_PASCAL	
idc.ASCSTR_TERMCHR	ida_nalt.STRTYPE_TERMCHR	
idc.ASCSTR_ULEN2	ida_nalt.STRTYPE_LEN2_16	
idc.ASCSTR_ULEN4	ida_nalt.STRTYPE_LEN4_16	
idc.ASCSTR_UNICODE	ida_nalt.STRTYPE_C_16	
idc.DOUNK_SIMPLE	ida_bytes.DELIT_SIMPLE	
idc.DOUNK_EXPAND	ida_bytes.DELIT_EXPAND	
idc.DOUNK_DELNAMES	ida_bytes.DELIT_DELNAMES	
idc.FF_ASCI	ida_bytes.FF_STRLIT	
idc.FF_DWRD	ida_bytes.FF_DWORD	
idc.FF_OWRD	ida_bytes.FF_OWORD	
idc.FF_QWRD	ida_bytes.FF_QWORD	
idc.FF_STRU	ida_bytes.FF_STRUCT	
idc.FF_TBYT	ida_bytes.FF_TBYTE	
idc.FIXUP_BYTE	ida_fixup.FIXUP_OFF8	
idc.FIXUP_CREATED	ida_fixup.FIXUPF_CREATED	
idc.FIXUP_EXTDEF	ida_fixup.FIXUPF_EXTDEF	
idc.FIXUP_REL	ida_fixup.FIXUPF_REL	
idc.FIXUP_UNUSED	ida_fixup.FIXUPF_UNUSED	
idc.GetFlags	ida_bytes.get_full_flags	
idc.ResumeProcess	idc.resume_process	
idc.isEnabled	ida_bytes.is_mapped	
idc.hasValue	ida_bytes.has_value	
idc.isByte	ida_bytes.is_byte	
idc.isWord	ida_bytes.is_word	
idc.isDwrd	ida_bytes.is_dword	
idc.isQwrd	ida_bytes.is_qword	
idc.isOwrd	ida_bytes.is_oword	
idc.isTbyt	ida_bytes.is_tbyte	
idc.isFloat	ida_bytes.is_float	
idc.isDouble	ida_bytes.is_double	
idc.isASCII	ida_bytes.is_strlit	
idc.isStruct	ida_bytes.is_struct	
idc.isAlign	ida_bytes.is_align	
idc.isChar0	ida_bytes.is_char0	
idc.isChar1	ida_bytes.is_char1	
idc.isCode	ida_bytes.is_code	
idc.isData	ida_bytes.is_data	
idc.isDefArg0	ida_bytes.is_defarg0	
idc.isDefArg1	ida_bytes.is_defarg1	
idc.isEnum0	ida_bytes.is_enum0	
idc.isEnum1	ida_bytes.is_enum1	
idc.isFlow	ida_bytes.is_flow	
idc.isHead	ida_bytes.is_head	
idc.isLoaded	ida_bytes.is_loaded	
idc.isOff0	ida_bytes.is_off0	
idc.isOff1	ida_bytes.is_off1	
idc.isPackReal	ida_bytes.is_pack_real	
idc.isSeg0	ida_bytes.is_seg0	
idc.isSeg1	ida_bytes.is_seg1	
idc.isStkvar0	ida_bytes.is_stkvar0	
idc.isStkvar1	ida_bytes.is_stkvar1	
idc.isStroff0	ida_bytes.is_stroff0	
idc.isStroff1	ida_bytes.is_stroff1	
idc.isTail	ida_bytes.is_tail	
idc.isUnknown	ida_bytes.is_unknown	
idc.SEGDEL_KEEP	ida_segment.SEGMOD_KEEP	
idc.SEGDEL_PERM	ida_segment.SEGMOD_KILL	
idc.SEGDEL_SILENT	ida_segment.SEGMOD_SILENT	
idc.SETPROC_ALL	ida_idp.SETPROC_LOADER_NON_FATAL	
idc.SETPROC_COMPAT	ida_idp.SETPROC_IDB	
idc.SETPROC_FATAL	ida_idp.SETPROC_LOADER	
idc.INF_CHANGE_COUNTER	idc.INF_DATABASE_CHANGE_COUNT	
idc.INF_LOW_OFF	idc.INF_LOWOFF	
idc.INF_HIGH_OFF	idc.INF_HIGHOFF	
idc.INF_START_PRIVRANGE	idc.INF_PRIVRANGE_START_EA	
idc.INF_END_PRIVRANGE	idc.INF_PRIVRANGE_END_EA	
idc.INF_TYPE_XREFS	idc.INF_TYPE_XREFNUM	
idc.INF_REFCMTS	idc.INF_REFCMTNUM	
idc.INF_XREFS	idc.INF_XREFFLAG	
idc.INF_NAMELEN	idc.INF_MAX_AUTONAME_LEN	
idc.INF_SHORT_DN	idc.INF_SHORT_DEMNAMES	
idc.INF_LONG_DN	idc.INF_LONG_DEMNAMES	
idc.INF_CMTFLAG	idc.INF_CMTFLG	
idc.INF_BORDER	idc.INF_LIMITER	
idc.INF_BINPREF	idc.INF_BIN_PREFIX_SIZE	
idc.INF_COMPILER	idc.INF_CC_ID	
idc.INF_MODEL	idc.INF_CC_CM	
idc.INF_SIZEOF_INT	idc.INF_CC_SIZE_I	
idc.INF_SIZEOF_BOOL	idc.INF_CC_SIZE_B	
idc.INF_SIZEOF_ENUM	idc.INF_CC_SIZE_E	
idc.INF_SIZEOF_ALGN	idc.INF_CC_DEFALIGN	
idc.INF_SIZEOF_SHORT	idc.INF_CC_SIZE_S	
idc.INF_SIZEOF_LONG	idc.INF_CC_SIZE_L	
idc.INF_SIZEOF_LLONG	idc.INF_CC_SIZE_LL	
idc.INF_SIZEOF_LDBL	idc.INF_CC_SIZE_LDBL	
idc.REF_VHIGH	ida_nalt.V695_REF_VHIGH	
idc.REF_VLOW	ida_nalt.V695_REF_VLOW	
idc.UTP_STRUCT	ida_typeinf.UTP_STRUCT	
idc.UTP_ENUM	ida_typeinf.UTP_ENUM	
idc.GetOpnd	idc.print_operand	
idc.patch_long	ida_bytes.patch_dword	
idc.python_on()	ida_loader.load_and_run_plugin("idapython", 3)	
idc.RunPythonStatement	idc.exec_python	
idc.GetManyBytes	idc.get_bytes	
idc.GetString	idc.get_strlit_contents	
idc.ClearTraceFile	idc.clear_trace	
idc.FindBinary	idc.find_binary	
idc.FindText	idc.find_text	
idc.NextHead	idc.next_head	
idc.PrevHead	idc.prev_head	
idc.ProcessUiAction	ida_kernwin.process_ui_action	
idc.SaveBase	idc.save_database	
idc.GetProcessorName()	ida_ida.inf_get_procname()	
idc.SegStart	idc.get_segm_start	
idc.SegEnd	idc.get_segm_end	
idc.SetSegmentType	idc.set_segm_type'''

import os
import sys
from os import walk

def convert(_file):
	fd = open(_file)
	f_data = "import ida_bytes\n"
	f_data += fd.read()
	fd.close()

	s = data.split("\n")
	for i in s:
		t = i.strip()
		syms = t.split("\t")
		before = syms[0]
		after = syms[1]

		if "(" in after:
			before = syms[0].split("(")[0]
			after = syms[1].split("(")[0]

		f_data = f_data.replace(before + "(", after + "(")

	fd = open(_file, "w")
	fd.write(f_data)
	fd.close()

if __name__ == "__main__":
	for (dirpath, dirnames, filenames) in walk("./"):
		for filename in filenames:
			if ".py" in filename and "convert.py" not in filename:
				convert(dirpath + "/" + filename)
				print("done -> " + dirpath + "/" + filename)


